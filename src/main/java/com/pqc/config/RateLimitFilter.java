package com.pqc.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Per-IP token-bucket rate limiter for the abusable endpoints.
 *
 * <p>Replaces the planned Google sign-in gate for the sandbox: the primitives
 * surface stays public, but each client IP gets a capped budget so a single
 * bad actor can't pin the JNI provider. Three independent buckets:
 *
 * <ul>
 *   <li><b>Sandbox primitives</b> ({@code /api/v1/sandbox/primitives/**} POSTs):
 *   default 60 req / minute / IP — engineers can experiment freely.</li>
 *
 *   <li><b>Scanner</b> ({@code /api/v1/scan**}): default 10 req / minute / IP
 *   — scans take seconds, so a tighter limit avoids tying up the executor.</li>
 *
 *   <li><b>Demo request</b> ({@code /api/v1/public/demo/request}): default 5
 *   req / minute / IP — one-shot form, conservative cap to prevent spam.</li>
 * </ul>
 *
 * <p>GETs for {@code /algorithms} and {@code /health} on the sandbox are
 * exempt — they're static catalog responses. CORS preflight (OPTIONS) is
 * also always exempt so the SPA's preflight chatter doesn't burn budget.
 *
 * <p>In-memory only — fine for the single-instance demo deployment. If we
 * scale to multiple replicas, swap to Bucket4j + Redis.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    // Cap the map so a flood of unique IPs (real or spoofed via XFF) can't
    // grow it without bound. Beyond MAX_CLIENTS the oldest evictable bucket
    // is dropped — worst case a previously-good IP gets a fresh budget.
    private static final int MAX_CLIENTS = 50_000;

    private final boolean enabled;
    private final int sandboxRpm;
    private final int sandboxBurst;
    private final int scannerRpm;
    private final int scannerBurst;
    private final int demoRpm;
    private final int demoBurst;

    private final ConcurrentMap<String, TokenBucket> sandboxBuckets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, TokenBucket> scannerBuckets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, TokenBucket> demoBuckets = new ConcurrentHashMap<>();
    private final AtomicInteger rejectionCount = new AtomicInteger();

    public RateLimitFilter(
            @Value("${app.ratelimit.enabled:true}") boolean enabled,
            @Value("${app.ratelimit.sandbox.rpm:60}") int sandboxRpm,
            @Value("${app.ratelimit.sandbox.burst:20}") int sandboxBurst,
            @Value("${app.ratelimit.scanner.rpm:10}") int scannerRpm,
            @Value("${app.ratelimit.scanner.burst:5}") int scannerBurst,
            @Value("${app.ratelimit.demo.rpm:5}") int demoRpm,
            @Value("${app.ratelimit.demo.burst:3}") int demoBurst) {
        this.enabled = enabled;
        this.sandboxRpm = sandboxRpm;
        this.sandboxBurst = sandboxBurst;
        this.scannerRpm = scannerRpm;
        this.scannerBurst = scannerBurst;
        this.demoRpm = demoRpm;
        this.demoBurst = demoBurst;
        if (enabled) {
            log.info("Rate limiting enabled: sandbox={}/min(burst {}), scanner={}/min(burst {}), demo={}/min(burst {})",
                    sandboxRpm, sandboxBurst, scannerRpm, scannerBurst, demoRpm, demoBurst);
        } else {
            log.warn("Rate limiting DISABLED — app.ratelimit.enabled=false. Public endpoints have no per-IP budget.");
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!enabled || "OPTIONS".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        Bucket bucket = bucketFor(request);
        if (bucket == null) {
            chain.doFilter(request, response);
            return;
        }

        String ip = clientIp(request);
        TokenBucket tb = bucket.map.computeIfAbsent(ip, k -> {
            if (bucket.map.size() >= MAX_CLIENTS) evictOne(bucket.map);
            return new TokenBucket(bucket.burst, bucket.rpm);
        });

        if (tb.tryConsume()) {
            chain.doFilter(request, response);
            return;
        }

        int total = rejectionCount.incrementAndGet();
        // Sampled WARN so a burst doesn't flood the log; the metric below
        // still increments on every rejection.
        if (total % 50 == 1) {
            log.warn("Rate-limit reject: ip={} path={} bucket={} (total rejections so far: {})",
                    ip, request.getRequestURI(), bucket.label, total);
        }

        response.setStatus(429);
        response.setHeader("Retry-After", "60");
        response.setContentType("application/json");
        response.getWriter().write(String.format(
                "{\"status\":\"error\",\"message\":\"Rate limit exceeded for %s. Retry in ~60s.\",\"bucket\":\"%s\"}",
                bucket.label, bucket.label));
    }

    private Bucket bucketFor(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.startsWith("/api/v1/sandbox/primitives/")) {
            // Catalog + health are cheap and idempotent — skip them.
            if (path.endsWith("/algorithms") || path.endsWith("/health")) return null;
            return new Bucket("sandbox", sandboxBuckets, sandboxRpm, sandboxBurst);
        }
        if (path.startsWith("/api/v1/scan")) {
            return new Bucket("scanner", scannerBuckets, scannerRpm, scannerBurst);
        }
        if (path.equals("/api/v1/public/demo/request")) {
            return new Bucket("demo-request", demoBuckets, demoRpm, demoBurst);
        }
        return null;
    }

    private static String clientIp(HttpServletRequest request) {
        // Honour XFF when present (deployments behind a proxy). Take the
        // leftmost entry — that's the original client before the proxy chain.
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int comma = xff.indexOf(',');
            return (comma > 0 ? xff.substring(0, comma) : xff).trim();
        }
        return request.getRemoteAddr();
    }

    private static void evictOne(ConcurrentMap<String, TokenBucket> map) {
        // Drop one entry to make room — order doesn't matter much; this only
        // fires past 50k unique IPs, which is well past the legitimate range.
        map.keySet().stream().findAny().ifPresent(map::remove);
    }

    /** A bucket selection (label, backing map, and the per-IP limits to apply). */
    private record Bucket(String label, ConcurrentMap<String, TokenBucket> map, int rpm, int burst) {}

    /**
     * Token bucket — {@code capacity} tokens, refilled continuously at
     * {@code refillPerMinute} tokens per minute. Calls are constant-time and
     * thread-safe via a synchronized {@link #tryConsume()}.
     */
    private static final class TokenBucket {
        private final double capacity;
        private final double refillPerNano;
        private double tokens;
        private long lastRefillNanos;

        TokenBucket(int capacity, int refillPerMinute) {
            this.capacity = capacity;
            this.refillPerNano = refillPerMinute / 60_000_000_000d;
            this.tokens = capacity;
            this.lastRefillNanos = System.nanoTime();
        }

        synchronized boolean tryConsume() {
            long now = System.nanoTime();
            tokens = Math.min(capacity, tokens + (now - lastRefillNanos) * refillPerNano);
            lastRefillNanos = now;
            if (tokens >= 1d) {
                tokens -= 1d;
                return true;
            }
            return false;
        }
    }
}
