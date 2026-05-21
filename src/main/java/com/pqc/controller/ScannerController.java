package com.pqc.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * TLS posture scanner. Two-phase observation of a remote endpoint:
 *
 * <ol>
 *   <li><b>JSSE handshake (always).</b> A pure-Java TLS connection via
 *   {@link SSLSocket} captures the TLS version, ciphersuite, certificate
 *   chain, and (for TLS 1.2) the kex from the ciphersuite name. No process
 *   spawn, no openssl dependency for the common path. Hostname verification
 *   is disabled because we're inspecting third-party endpoints — including
 *   ones with self-signed or expired certs — not making trusted
 *   connections.</li>
 *
 *   <li><b>Optional PQC capability probe.</b> Only when the JSSE
 *   handshake succeeds we shell out to {@code openssl s_client} with
 *   {@code -groups X25519MLKEM768} to test whether the remote server
 *   would negotiate a PQC hybrid group. This is the one bit of data
 *   stock Java cannot give us, because JSSE has no native ML-KEM
 *   support. We capture only that bit; everything else comes from
 *   Phase 1.</li>
 * </ol>
 *
 * <p>The PQC probe requires {@code openssl} (3.x recommended) on the host
 * with the Qudo OpenSSL provider installed and activated in
 * {@code openssl.cnf} — see the Get Started guide. When openssl isn't
 * available, the scan still works and just reports PQC capability as
 * "not detected".</p>
 *
 * Ported from the legacy ui-dashboard CryptoInventoryController; URL moved
 * from {@code /api/crypto-inventory/scan} to {@code /api/v1/scan} to fit the
 * new portal's API namespace.
 */
@RestController
@RequestMapping("/api/v1/scan")
public class ScannerController {

    private static final Logger log = LoggerFactory.getLogger(ScannerController.class);
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9.\\-_]+:[0-9]{1,5}$");
    private static Boolean opensslAvailableCache = null;

    @Value("${app.scanner.enabled:true}")
    private boolean scannerEnabled;

    // Production default is false — the scanner is exposed on a public
    // endpoint and must not be turnable into an SSRF reflector against
    // the BE's internal network. Local development can override this in
    // application-local.properties.
    @Value("${app.scanner.allow-private-addresses:false}")
    private boolean allowPrivateAddresses;

    @Value("${app.scanner.max-output-bytes:65536}")
    private int maxOutputBytes;

    @PostMapping
    public ResponseEntity<?> scan(@RequestBody Map<String, String> request) {
        if (!scannerEnabled) {
            return ResponseEntity.status(503).body(Map.of(
                    "error", "Scanner is disabled in this environment",
                    "hint", "Set APP_SCANNER_ENABLED=true to enable."));
        }
        String host = normalizeHost(request.getOrDefault("host", "localhost:8443"));
        if (!isValidHost(host)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Invalid host format",
                    "hint", "Use hostname or IP with optional port (e.g. example.com:443 or 10.0.0.1:8443)"));
        }
        // Single-shot resolve + SSRF validation. Done once at the start
        // of the request, then the resolved InetAddress is passed to
        // BOTH the JSSE handshake and the openssl probe so neither
        // re-resolves and an attacker-controlled DNS server can't flip
        // between a public IP (passes the check) and a private IP (used
        // for the connection).
        Resolved resolved;
        try {
            resolved = resolveAndValidate(host);
        } catch (java.net.UnknownHostException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Couldn't resolve hostname",
                    "hint", "\"" + hostnamePart(host) + "\" doesn't resolve. Check the spelling, or verify the host exists in public DNS."));
        }
        if (resolved.rejection() != null) {
            log.warn("Scanner request rejected (SSRF guard): {}", host);
            return ResponseEntity.status(403).body(Map.of(
                    "error", "Target rejected by SSRF guard",
                    "hint", resolved.rejection()));
        }
        // openssl is no longer required for the basic scan — JSSE does it.
        // If openssl is missing we just skip the TLS 1.3 group probe.

        try {
            String rawOutput = observeTlsViaJsse(host, resolved.address());
            Map<String, String> tlsInfo = parseTlsInfo(rawOutput);
            // For TLS 1.3 sessions, JSSE doesn't tell us the negotiated
            // named group — recover it via a small openssl probe. The
            // probe advertises X25519MLKEM768 first, so a PQC-capable
            // server lights up; otherwise we still get the classical
            // group the server picked. Skipped for TLS 1.2 (kex is in
            // the ciphersuite name already) and when openssl is absent.
            if ("TLSv1.3".equals(tlsInfo.get("tlsVersion"))) {
                String group = probeTls13Group(host, resolved.address());
                if (group != null) {
                    tlsInfo.put("keyExchange", group);
                    rawOutput += "# probe: tls1_3-group\nNegotiated TLS1.3 group: " + group + "\n";
                }
            }
            List<Map<String, String>> inventory = buildInventory(tlsInfo);
            int score = calculateScore(inventory);
            List<Map<String, Object>> checklist = buildChecklist(tlsInfo);
            String scoreLabel = score >= 80 ? "Quantum-Ready" : score >= 50 ? "Partially Ready" : "At Risk";

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("endpoint", host);
            result.put("score", score);
            result.put("scoreLabel", scoreLabel);
            result.put("tlsInfo", tlsInfo);
            result.put("inventory", inventory);
            result.put("checklist", checklist);
            result.put("rawOutput", rawOutput);
            result.put("scannedAt", System.currentTimeMillis());

            return ResponseEntity.ok(result);
        } catch (javax.net.ssl.SSLHandshakeException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "TLS handshake failed",
                    "hint", e.getMessage() != null ? e.getMessage() : "Server refused the handshake.",
                    "endpoint", host));
        } catch (java.net.SocketTimeoutException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Connection timed out",
                    "hint", "Host resolved but didn't respond on TLS within 5 s. Check the port and reachability.",
                    "endpoint", host));
        } catch (java.net.ConnectException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Connection refused",
                    "hint", e.getMessage() != null ? e.getMessage() : "Port is closed or filtered.",
                    "endpoint", host));
        } catch (Exception e) {
            log.warn("Scan error for {}: {}", host, e.toString());
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Scan failed unexpectedly",
                    "hint", e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName(),
                    "endpoint", host));
        }
    }

    @PostMapping("/bulk")
    public ResponseEntity<?> scanBulk(@RequestBody Map<String, Object> request) {
        if (!scannerEnabled) {
            return ResponseEntity.status(503).body(Map.of("error", "Scanner is disabled in this environment"));
        }
        @SuppressWarnings("unchecked")
        List<String> hosts = (List<String>) request.getOrDefault("hosts", List.of());
        // openssl is no longer required — JSSE handles the basic scan.
        // The PQC capability probe is best-effort and silently skipped
        // when openssl isn't present.

        List<Map<String, Object>> results = new ArrayList<>();
        for (String rawHost : hosts) {
            String host = normalizeHost(rawHost);
            if (!isValidHost(host)) {
                results.add(Map.of("endpoint", host, "score", 0, "scoreLabel", "Error",
                        "error", "Invalid host format."));
                continue;
            }
            Resolved resolved;
            try {
                resolved = resolveAndValidate(host);
            } catch (java.net.UnknownHostException e) {
                results.add(Map.of("endpoint", host, "score", 0, "scoreLabel", "Error",
                        "error", "DNS resolution failed for \"" + hostnamePart(host) + "\"."));
                continue;
            }
            if (resolved.rejection() != null) {
                results.add(Map.of("endpoint", host, "score", 0, "scoreLabel", "Rejected",
                        "error", "SSRF guard: " + resolved.rejection()));
                continue;
            }
            try {
                String rawOutput = observeTlsViaJsse(host, resolved.address());
                Map<String, String> tlsInfo = parseTlsInfo(rawOutput);
                if ("TLSv1.3".equals(tlsInfo.get("tlsVersion"))) {
                    String group = probeTls13Group(host, resolved.address());
                    if (group != null) tlsInfo.put("keyExchange", group);
                }
                List<Map<String, String>> inventory = buildInventory(tlsInfo);
                int score = calculateScore(inventory);
                String label = score >= 80 ? "Quantum-Ready" : score >= 50 ? "Partially Ready" : "At Risk";
                results.add(Map.of("endpoint", host, "score", score, "scoreLabel", label,
                        "keyExchange", tlsInfo.getOrDefault("keyExchange", "unknown"),
                        "tlsVersion", tlsInfo.getOrDefault("tlsVersion", "unknown"),
                        "certSignature", tlsInfo.getOrDefault("certSignature", "unknown")));
            } catch (Exception e) {
                results.add(Map.of("endpoint", host, "score", 0, "scoreLabel", "Error",
                        "error", e.getMessage() != null ? e.getMessage() : "Scan failed"));
            }
        }
        return ResponseEntity.ok(Map.of("results", results, "scannedAt", System.currentTimeMillis()));
    }

    // ===== Host normalization & validation =====

    private String normalizeHost(String input) {
        input = input.trim();
        input = input.replaceFirst("^https?://", "");
        input = input.split("/")[0];
        if (!input.contains(":")) input = input + ":443";
        return input;
    }

    private boolean isValidHost(String host) {
        return host != null && HOST_PATTERN.matcher(host).matches();
    }

    /**
     * SSRF defence. Resolves the hostname and rejects targets that point at
     * loopback / link-local / RFC-1918 / multicast / cloud metadata addresses
     * unless {@code app.scanner.allow-private-addresses} is true.
     */

    /** Output of a single-shot resolve+SSRF validation. */
    private record Resolved(InetAddress address, String rejection) {}

    /** The hostname portion of a host[:port] string, for SNI / error messages. */
    private static String hostnamePart(String host) {
        return host.contains(":") ? host.substring(0, host.lastIndexOf(':')) : host;
    }

    /**
     * Resolve DNS once and validate the result against the SSRF policy
     * in a single shot. The returned {@link Resolved#address()} is the
     * concrete IP that downstream code MUST connect to — passing the
     * hostname back to JSSE / openssl would let an attacker-controlled
     * authoritative DNS server flip between a public IP (which passes
     * this check) and a private IP (which gets used for the actual
     * connection). This is the DNS-rebinding mitigation.
     *
     * <p>If any address the hostname resolves to is private or
     * reserved, the whole hostname is rejected — not just the offending
     * address — because a re-resolution at connect time would pick a
     * different address from the same set.</p>
     *
     * @throws java.net.UnknownHostException when the hostname doesn't resolve
     */
    private Resolved resolveAndValidate(String host) throws java.net.UnknownHostException {
        String hostname = hostnamePart(host);
        InetAddress[] addrs = InetAddress.getAllByName(hostname);
        if (addrs.length == 0) {
            throw new java.net.UnknownHostException(hostname);
        }
        if (!allowPrivateAddresses) {
            for (InetAddress addr : addrs) {
                String rejection = privateOrReservedReason(addr);
                if (rejection != null) return new Resolved(null, rejection);
            }
        }
        // Prefer IPv4 for the connection — broader server support and the
        // SSRF check has covered both families regardless.
        InetAddress picked = Arrays.stream(addrs)
                .filter(a -> a instanceof Inet4Address)
                .findFirst()
                .orElse(addrs[0]);
        return new Resolved(picked, null);
    }

    /**
     * Returns a human-readable rejection reason if the address falls in
     * a private/reserved range, otherwise {@code null}. Goes beyond
     * Java's built-in checks ({@code isSiteLocalAddress} is IPv4-only,
     * {@code isLinkLocalAddress} misses some ranges) by inspecting the
     * raw byte prefix for IPv6 ULA and IPv4-mapped IPv6.
     */
    private String privateOrReservedReason(InetAddress addr) {
        if (addr.isAnyLocalAddress()) return "wildcard (0.0.0.0, ::)";
        if (addr.isLoopbackAddress()) return "loopback (127.0.0.0/8, ::1)";
        if (addr.isLinkLocalAddress()) return "link-local (169.254.0.0/16, fe80::/10) — includes cloud metadata endpoints";
        if (addr.isSiteLocalAddress()) return "RFC-1918 private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)";
        if (addr.isMulticastAddress()) return "multicast";
        byte[] b = addr.getAddress();
        // IPv4 broadcast & shared address space — Java doesn't flag these.
        if (b.length == 4) {
            int o0 = b[0] & 0xFF;
            if (o0 == 255) return "broadcast (255.0.0.0/8)";
            if (o0 == 100 && (b[1] & 0xFF) >= 64 && (b[1] & 0xFF) <= 127) {
                return "CGNAT shared address space (100.64.0.0/10)";
            }
        }
        // IPv6 unique local addresses (ULA) — fc00::/7. Java's
        // isSiteLocalAddress doesn't cover this; we check the byte prefix.
        if (b.length == 16 && (b[0] & 0xFE) == 0xFC) {
            return "IPv6 unique local address (fc00::/7)";
        }
        // IPv6 IPv4-mapped (::ffff:0:0/96). Re-check the embedded v4 so
        // an attacker can't smuggle a private v4 inside a v6 wrapper.
        if (b.length == 16
                && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0
                && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0
                && b[8] == 0 && b[9] == 0
                && (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF) {
            try {
                InetAddress embedded = InetAddress.getByAddress(
                        new byte[]{b[12], b[13], b[14], b[15]});
                String inner = privateOrReservedReason(embedded);
                if (inner != null) return "IPv4-mapped IPv6 wrapping " + inner;
            } catch (Exception ignored) {
                return "IPv4-mapped IPv6 with unparseable embedded address";
            }
        }
        // 2001:db8::/32 — documentation range, never legitimate traffic.
        if (b.length == 16 && b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == (byte) 0xB8) {
            return "IPv6 documentation range (2001:db8::/32)";
        }
        return null;
    }

    private boolean opensslAvailable() {
        if (opensslAvailableCache != null) return opensslAvailableCache;
        try {
            ProcessBuilder pb = new ProcessBuilder("openssl", "version").redirectErrorStream(true);
            scrubEnv(pb);
            Process p = pb.start();
            p.waitFor(3, TimeUnit.SECONDS);
            opensslAvailableCache = p.exitValue() == 0;
        } catch (Exception e) {
            opensslAvailableCache = false;
        }
        return opensslAvailableCache;
    }

    /**
     * Strip the inherited JVM environment down to a minimal allowlist
     * before spawning openssl. Without this, every env var on the BE —
     * DB passwords, signing keys, AWS creds — is visible to the child.
     * openssl normally doesn't read these, but a tampered binary or a
     * malicious {@code OPENSSL_CONF} / {@code LD_PRELOAD} could.
     */
    private void scrubEnv(ProcessBuilder pb) {
        String path = System.getenv("PATH");
        pb.environment().clear();
        if (path != null) pb.environment().put("PATH", path);
        // Force a sane locale so openssl output is parseable across hosts.
        pb.environment().put("LC_ALL", "C");
    }

    // ===== Probe stages =====

    /**
     * Phase 1: pure-Java TLS handshake. Captures protocol version,
     * ciphersuite, the leaf certificate's signature algorithm, and the
     * peer principal. For TLS 1.2 the kex (ECDHE/DHE/RSA) is embedded in
     * the ciphersuite name; for TLS 1.3 JSSE doesn't expose the
     * negotiated named group, so we mark it as "not reported" and let
     * the PQC probe in phase 2 detect quantum-safe capability.
     *
     * Hostname verification is OFF and the trust manager accepts any
     * certificate. We're inspecting third-party endpoints — including
     * ones with self-signed, expired, or hostname-mismatched certs.
     * We are not exchanging data with them; we just want to read the
     * handshake.
     *
     * @return an output blob in the same line-oriented format the
     *         original openssl shell-out produced, so
     *         {@link #parseTlsInfo(String)} keeps working unchanged.
     */
    private String observeTlsViaJsse(String host, InetAddress resolvedAddr) throws Exception {
        String hostname = hostnamePart(host);
        int port = host.contains(":")
                ? Integer.parseInt(host.substring(host.lastIndexOf(':') + 1))
                : 443;

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] c, String t) {}
            public void checkServerTrusted(X509Certificate[] c, String t) {}
        }}, new SecureRandom());

        SSLSocketFactory factory = ctx.getSocketFactory();
        try (SSLSocket sock = (SSLSocket) factory.createSocket()) {
            // Connect to the pre-resolved IP, NOT the hostname. Prevents
            // a second DNS lookup that could land on a different (private)
            // address. See resolveAndValidate() javadoc.
            sock.connect(new InetSocketAddress(resolvedAddr, port), 5_000);
            sock.setSoTimeout(5_000);
            sock.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            // Disable hostname verification — see method javadoc — but
            // do send the original hostname in SNI so name-based virtual
            // hosting at the target still works.
            SSLParameters params = sock.getSSLParameters();
            params.setEndpointIdentificationAlgorithm(null);
            params.setServerNames(List.of(new SNIHostName(hostname)));
            sock.setSSLParameters(params);
            sock.startHandshake();

            SSLSession session = sock.getSession();
            StringBuilder out = new StringBuilder("# probe: jsse\n");
            out.append("Protocol version: ").append(session.getProtocol()).append('\n');
            out.append("Ciphersuite: ").append(session.getCipherSuite()).append('\n');
            Certificate[] chain = session.getPeerCertificates();
            if (chain.length > 0 && chain[0] instanceof X509Certificate leaf) {
                out.append("Signature type: ").append(leaf.getSigAlgName()).append('\n');
                out.append("Peer certificate: ").append(leaf.getSubjectX500Principal().getName()).append('\n');
            }
            return out.toString();
        }
    }

    /**
     * Phase 2: tiny openssl probe to recover the negotiated TLS 1.3
     * named group, which JSSE doesn't expose via the standard
     * {@link SSLSession} API in Java 17. Advertises the PQC hybrid
     * group first, then classical fallbacks. If the server speaks PQC
     * we'll see {@code X25519MLKEM768}; otherwise we'll see whichever
     * classical group the server picked from the rest of the list.
     *
     * Only meaningful for TLS 1.3 connections — for TLS 1.2 the kex is
     * embedded in the ciphersuite name and {@link #deriveKeyExchange}
     * already handles that. Best-effort; when openssl isn't installed
     * or the probe times out we leave the kex as "TLS 1.3 group not
     * reported".
     *
     * @return the negotiated group name (e.g. {@code "X25519MLKEM768"}
     *         or {@code "X25519"}), or {@code null} when we couldn't
     *         determine it.
     */
    private String probeTls13Group(String host, InetAddress resolvedAddr) {
        if (!opensslAvailable()) return null;
        String hostname = hostnamePart(host);
        int port = host.contains(":")
                ? Integer.parseInt(host.substring(host.lastIndexOf(':') + 1))
                : 443;
        // Connect by literal IP (DNS-rebinding-safe), force SNI to the
        // original hostname so the server picks the right vhost.
        String connectArg = resolvedAddr instanceof Inet6Address
                ? "[" + resolvedAddr.getHostAddress() + "]:" + port
                : resolvedAddr.getHostAddress() + ":" + port;

        Process p = null;
        ExecutorService exec = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "openssl", "s_client",
                    "-connect", connectArg,
                    "-servername", hostname,
                    "-brief", "-tls1_3",
                    "-groups", "X25519MLKEM768:X25519:P-384:P-256");
            pb.redirectErrorStream(true);
            scrubEnv(pb);
            p = pb.start();
            try { p.getOutputStream().write("Q\n".getBytes()); p.getOutputStream().flush(); }
            catch (Exception ignored) { /* process may have exited already */ }

            // Hard read deadline via a worker thread. If openssl hangs
            // without writing anything, BufferedReader.readLine blocks
            // forever and the later waitFor() never fires. Future.get
            // with a timeout caps the total time we'll wait for output.
            final Process proc = p;
            exec = Executors.newSingleThreadExecutor();
            Future<String> task = exec.submit(() -> {
                StringBuilder out = new StringBuilder();
                try (BufferedReader r = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        out.append(line).append('\n');
                        if (out.length() >= maxOutputBytes) break;
                    }
                }
                return out.toString();
            });

            String raw;
            try {
                raw = task.get(5, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                log.debug("TLS 1.3 group probe timed out for {}", host);
                return null;
            }
            // openssl 3.x with -brief reports the group as either
            //   "Negotiated TLS1.3 group: <name>"   (older line)
            //   "Peer Temp Key: <name>, <bits> bits"  (3.x +)
            // Accept both. Strip the trailing ", N bits" suffix.
            Matcher m = Pattern.compile("Negotiated TLS1\\.3 group:\\s*(\\S+)").matcher(raw);
            if (m.find()) return m.group(1).trim();
            m = Pattern.compile("(?:Server|Peer) Temp Key:\\s*([^,\\n]+)").matcher(raw);
            if (m.find()) return m.group(1).trim();
            return null;
        } catch (Exception e) {
            log.debug("TLS 1.3 group probe failed for {}: {}", host, e.toString());
            return null;
        } finally {
            if (p != null && p.isAlive()) p.destroyForcibly();
            if (exec != null) exec.shutdownNow();
        }
    }

    // ===== Parse + assess =====

    private Map<String, String> parseTlsInfo(String raw) {
        Map<String, String> info = new LinkedHashMap<>();
        info.put("tlsVersion", extractValue(raw, "Protocol version:\\s*(.+)"));
        info.put("cipher", extractValue(raw, "Ciphersuite:\\s*(.+)"));
        info.put("certSignature", extractValue(raw, "Signature type:\\s*(.+)"));
        info.put("peerCert", extractValue(raw, "Peer certificate:\\s*(.+)"));
        info.put("hashUsed", extractValue(raw, "Hash used:\\s*(.+)"));
        info.put("keyExchange", deriveKeyExchange(raw, info.get("tlsVersion"), info.get("cipher")));

        if (raw.contains("connect:errno") || raw.contains("Connection refused")
                || raw.contains("no protocols available") || raw.contains("handshake failure")) {
            info.put("error", "Connection failed or handshake rejected");
        }
        return info;
    }

    private String deriveKeyExchange(String raw, String tlsVersion, String cipher) {
        String v = extractValue(raw, "Negotiated TLS1\\.3 group:\\s*(.+)");
        if (!v.equals("unknown")) return v;
        v = extractValue(raw, "(?:Server|Peer) Temp Key:\\s*([^,\\n]+)");
        if (!v.equals("unknown")) return v.trim();

        if (cipher != null && !cipher.equals("unknown")) {
            String upper = cipher.toUpperCase();
            if (upper.contains("ECDHE")) return "ECDHE (classical)";
            if (upper.contains("DHE")) return "DHE (classical)";
            if (upper.startsWith("TLS_") && tlsVersion != null && tlsVersion.contains("1.3")) {
                return "TLS 1.3 group not reported";
            }
            if (upper.contains("RSA")) return "RSA (classical, no forward secrecy)";
        }
        if (tlsVersion == null || tlsVersion.equals("unknown")) return "not available (handshake failed)";
        return "not reported";
    }

    private String extractValue(String text, String regex) {
        Matcher m = Pattern.compile(regex).matcher(text);
        return m.find() ? m.group(1).trim() : "unknown";
    }

    private List<Map<String, String>> buildInventory(Map<String, String> tlsInfo) {
        List<Map<String, String>> inventory = new ArrayList<>();

        String tls = tlsInfo.getOrDefault("tlsVersion", "unknown");
        inventory.add(row("TLS Version", tls,
                tls.contains("1.3") ? "safe" : tls.contains("1.2") ? "review" : "at-risk",
                tls.contains("1.3") ? "TLS 1.3 supports PQC key exchange groups."
                        : "Upgrade to TLS 1.3. PQC key exchange requires TLS 1.3."));

        String kex = tlsInfo.getOrDefault("keyExchange", "unknown");
        String kexUpper = kex.toUpperCase();
        boolean hybridKex = kexUpper.contains("MLKEM") || kexUpper.contains("ML-KEM");
        boolean classicalEc = kexUpper.contains("ECDHE") || kexUpper.startsWith("X25519") || kexUpper.startsWith("P-");
        boolean weakKex = kexUpper.contains("RSA") || kexUpper.equals("DHE (CLASSICAL)");
        boolean undetermined = kex.equals("unknown") || kex.startsWith("not ") || kex.startsWith("TLS 1.3 group not");

        String kexStatus;
        String kexRecommendation;
        if (hybridKex) {
            kexStatus = "quantum-safe";
            kexRecommendation = "Hybrid PQC key exchange active (" + kex + "). Quantum-safe forward secrecy.";
        } else if (weakKex) {
            kexStatus = "at-risk";
            kexRecommendation = "RSA/static key exchange — no forward secrecy and vulnerable to future quantum attacks. Migrate to hybrid PQC.";
        } else if (classicalEc) {
            kexStatus = "at-risk";
            kexRecommendation = "Classical elliptic-curve key exchange (" + kex + "). Vulnerable to harvest-now-decrypt-later. Add hybrid PQC group X25519MLKEM768.";
        } else if (undetermined) {
            kexStatus = "review";
            kexRecommendation = "Could not determine key-exchange group from the handshake. Scan manually: openssl s_client -connect <host>:443";
        } else {
            kexStatus = "at-risk";
            kexRecommendation = "Unrecognized key exchange '" + kex + "'. Review manually and plan migration to hybrid PQC.";
        }
        inventory.add(row("Key Exchange", kex, kexStatus, kexRecommendation));

        String cipher = tlsInfo.getOrDefault("cipher", "unknown");
        boolean aes256 = cipher.contains("AES_256");
        boolean aes128 = cipher.contains("AES_128");
        inventory.add(row("Symmetric Cipher", cipher,
                aes256 ? "safe" : aes128 ? "review" : "at-risk",
                aes256 ? "AES-256-GCM. Symmetric ciphers are quantum-safe (Grover halves key strength — 256-bit remains 128-bit effective)."
                        : "Consider AES-256-GCM for maximum post-quantum symmetric security."));

        String certSig = tlsInfo.getOrDefault("certSignature", "unknown");
        boolean pqcCert = certSig.toLowerCase().contains("ml-dsa") || certSig.toLowerCase().contains("mldsa");
        boolean ecdsa = certSig.toLowerCase().contains("ecdsa");
        boolean rsa = certSig.toLowerCase().contains("rsa");
        inventory.add(row("Server Certificate", certSig,
                pqcCert ? "quantum-safe" : "at-risk",
                pqcCert ? "PQC certificate (ML-DSA). Server identity is quantum-safe."
                        : ecdsa ? "Classical ECDSA certificate. Vulnerable to quantum attack on server identity. Migrate to ML-DSA-65."
                        : rsa ? "Classical RSA certificate. Vulnerable to quantum attack. Migrate to ML-DSA-65."
                        : "Unknown certificate type. Review manually."));

        String hash = tlsInfo.getOrDefault("hashUsed", "unknown");
        inventory.add(row("Hash Algorithm", hash,
                hash.contains("384") || hash.contains("512") ? "safe" : hash.contains("256") ? "safe" : "review",
                "SHA-2/SHA-3 family is quantum-safe for hashing. Grover's attack is impractical for 256-bit+ hashes."));

        return inventory;
    }

    private Map<String, String> row(String component, String algorithm, String status, String recommendation) {
        Map<String, String> r = new LinkedHashMap<>();
        r.put("component", component);
        r.put("algorithm", algorithm);
        r.put("status", status);
        r.put("recommendation", recommendation);
        return r;
    }

    private int calculateScore(List<Map<String, String>> inventory) {
        int totalWeight = 0;
        int earnedWeight = 0;
        for (Map<String, String> item : inventory) {
            int weight = switch (item.get("component")) {
                case "Key Exchange" -> 40;
                case "Server Certificate" -> 25;
                case "TLS Version" -> 15;
                case "Symmetric Cipher" -> 10;
                case "Hash Algorithm" -> 10;
                default -> 10;
            };
            totalWeight += weight;
            earnedWeight += switch (item.get("status")) {
                case "quantum-safe", "safe" -> weight;
                case "review" -> weight / 2;
                default -> 0;
            };
        }
        return totalWeight > 0 ? (earnedWeight * 100) / totalWeight : 0;
    }

    private List<Map<String, Object>> buildChecklist(Map<String, String> tlsInfo) {
        List<Map<String, Object>> checklist = new ArrayList<>();
        String kex = tlsInfo.getOrDefault("keyExchange", "");
        String tls = tlsInfo.getOrDefault("tlsVersion", "");
        String cipher = tlsInfo.getOrDefault("cipher", "");

        checklist.add(check("TLS 1.3 Enabled", "Required for PQC key exchange groups.", tls.contains("1.3")));
        checklist.add(check("Hybrid PQC Key Exchange",
                "X25519MLKEM768 provides quantum-safe forward secrecy. Add to NGINX: ssl_ecdh_curve X25519MLKEM768:X25519:P-384",
                kex.contains("MLKEM")));
        checklist.add(check("AES-256 Symmetric Encryption",
                "256-bit symmetric cipher. Quantum-safe against Grover's algorithm.", cipher.contains("AES_256")));
        return checklist;
    }

    private Map<String, Object> check(String name, String description, boolean passed) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("name", name);
        item.put("description", description);
        item.put("passed", passed);
        return item;
    }
}
