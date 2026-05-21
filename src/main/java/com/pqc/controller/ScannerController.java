package com.pqc.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * TLS posture scanner. Shells out to the system openssl binary's s_client to
 * probe a target endpoint, then parses the handshake to assess PQC readiness.
 *
 * <p>Three probes are tried in order so classical servers still yield readable
 * info: TLS 1.3 with PQC groups, TLS 1.3 default, TLS 1.2 default. The first
 * probe that negotiates anything is annotated and returned.</p>
 *
 * <p>This requires {@code openssl} (3.x recommended) installed on the host
 * running the BE. For full PQC group detection ({@code X25519MLKEM768}), the
 * Qudo OpenSSL provider should be installed and activated in
 * {@code openssl.cnf} — see the Get Started guide.</p>
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

    @Value("${app.scanner.allow-private-addresses:true}")
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
        String ssrfRejection = checkSsrf(host);
        if (ssrfRejection != null) {
            log.warn("Scanner request rejected (SSRF guard): {}", host);
            return ResponseEntity.status(403).body(Map.of(
                    "error", "Target rejected by SSRF guard",
                    "hint", ssrfRejection));
        }
        // Resolve DNS up front. Without this, an unresolvable host (typo,
        // dead domain) takes ~30 s as openssl times out across all three
        // probes — and the resulting broken-pipe IOException leaks as a
        // 500. Fail fast with a clear message instead.
        String dnsRejection = resolveOrError(host);
        if (dnsRejection != null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Couldn't resolve hostname",
                    "hint", dnsRejection));
        }
        if (!opensslAvailable()) {
            return ResponseEntity.status(503).body(Map.of(
                    "error", "openssl binary not found on this server",
                    "hint", "Install openssl 3.x and ensure it's on PATH so the scanner can probe TLS endpoints."));
        }

        try {
            String rawOutput = runOpenssl(host);
            Map<String, String> tlsInfo = parseTlsInfo(rawOutput);
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
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", e.getMessage() != null ? e.getMessage() : "Scan failed",
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
        if (!opensslAvailable()) {
            return ResponseEntity.status(503).body(Map.of(
                    "error", "openssl binary not found on this server",
                    "hint", "Install openssl and ensure it's on PATH."));
        }

        List<Map<String, Object>> results = new ArrayList<>();
        for (String rawHost : hosts) {
            String host = normalizeHost(rawHost);
            if (!isValidHost(host)) {
                results.add(Map.of("endpoint", host, "score", 0, "scoreLabel", "Error",
                        "error", "Invalid host format."));
                continue;
            }
            String ssrfRejection = checkSsrf(host);
            if (ssrfRejection != null) {
                results.add(Map.of("endpoint", host, "score", 0, "scoreLabel", "Rejected",
                        "error", "SSRF guard: " + ssrfRejection));
                continue;
            }
            String dnsRejection = resolveOrError(host);
            if (dnsRejection != null) {
                results.add(Map.of("endpoint", host, "score", 0, "scoreLabel", "Error",
                        "error", dnsRejection));
                continue;
            }
            try {
                String rawOutput = runOpenssl(host);
                Map<String, String> tlsInfo = parseTlsInfo(rawOutput);
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
     * unless {@code app.scanner.allow-private-addresses} is true. Prevents
     * the scanner from being used as a reflector against internal services
     * (e.g. 169.254.169.254 metadata, 10.x kube-apiserver, 192.168.x routers).
     *
     * @return {@code null} when the target is acceptable, otherwise a
     *         human-readable rejection reason for the API response.
     */
    private String checkSsrf(String host) {
        if (allowPrivateAddresses) return null;
        String hostname = host.contains(":") ? host.substring(0, host.lastIndexOf(':')) : host;
        try {
            InetAddress[] addresses = InetAddress.getAllByName(hostname);
            for (InetAddress addr : addresses) {
                if (addr.isAnyLocalAddress()) return "wildcard / 0.0.0.0";
                if (addr.isLoopbackAddress()) return "loopback (127.0.0.0/8, ::1)";
                if (addr.isLinkLocalAddress()) return "link-local (169.254.0.0/16, fe80::/10) — includes cloud metadata endpoints";
                if (addr.isSiteLocalAddress()) return "RFC-1918 private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)";
                if (addr.isMulticastAddress()) return "multicast";
            }
            return null;
        } catch (Exception e) {
            return "DNS resolution failed for " + hostname;
        }
    }

    /**
     * Run DNS resolution against the hostname portion of {@code host} so
     * we can fail fast with an actionable error instead of letting
     * openssl spend ~30 s timing out across three probes.
     *
     * @return {@code null} when the hostname resolves; a human-readable
     *         error message ready for the JSON body when it doesn't.
     */
    private String resolveOrError(String host) {
        String hostname = host.contains(":") ? host.substring(0, host.lastIndexOf(':')) : host;
        try {
            InetAddress[] addrs = InetAddress.getAllByName(hostname);
            return addrs.length == 0
                    ? "DNS lookup returned no addresses for \"" + hostname + "\". Check the spelling."
                    : null;
        } catch (java.net.UnknownHostException e) {
            return "\"" + hostname + "\" doesn't resolve. Check the spelling, or verify the host exists in public DNS.";
        } catch (Exception e) {
            return "DNS lookup failed for \"" + hostname + "\": " + e.getMessage();
        }
    }

    private boolean opensslAvailable() {
        if (opensslAvailableCache != null) return opensslAvailableCache;
        try {
            Process p = new ProcessBuilder("openssl", "version").redirectErrorStream(true).start();
            p.waitFor(3, TimeUnit.SECONDS);
            opensslAvailableCache = p.exitValue() == 0;
        } catch (Exception e) {
            opensslAvailableCache = false;
        }
        return opensslAvailableCache;
    }

    // ===== Probe stages =====

    /**
     * Probe in stages so classical servers still yield readable info:
     *   1) TLS 1.3 + PQC groups (captures quantum-safe servers)
     *   2) TLS 1.3, default groups (captures classical TLS 1.3 — X25519/P-256)
     *   3) TLS 1.2 default (legacy servers; kex in cipher-suite name)
     */
    private String runOpenssl(String host) throws Exception {
        String[][] probes = {
                {"tls1_3-pqc", "-tls1_3", "-groups", "X25519MLKEM768:X25519:P-384"},
                {"tls1_3", "-tls1_3"},
                {"tls1_2", "-tls1_2"}
        };
        String lastOutput = "";
        for (String[] probe : probes) {
            String mode = probe[0];
            List<String> cmd = new ArrayList<>(List.of("openssl", "s_client", "-connect", host, "-brief"));
            for (int i = 1; i < probe.length; i++) cmd.add(probe[i]);

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.getOutputStream().write("Q\n".getBytes());
            p.getOutputStream().flush();

            // Cap captured output to prevent OOM from a malicious target. Once
            // we hit the cap we stop reading but keep the partial output for
            // parsing — the relevant TLS handshake lines come early.
            StringBuilder output = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    output.append(line).append("\n");
                    if (output.length() >= maxOutputBytes) {
                        log.warn("Scanner output cap hit for {} (probe={}); truncating", host, mode);
                        break;
                    }
                }
            }
            boolean completed = p.waitFor(10, TimeUnit.SECONDS);
            if (!completed) {
                p.destroyForcibly();
                p.waitFor(2, TimeUnit.SECONDS);  // give it a beat to die
                continue;
            }

            String raw = output.toString();
            lastOutput = raw;
            if (Pattern.compile("Protocol version:\\s*\\S+").matcher(raw).find()
                    || Pattern.compile("Ciphersuite:\\s*\\S+").matcher(raw).find()) {
                return "# probe: " + mode + "\n" + raw;
            }
        }
        if (lastOutput.isEmpty()) {
            throw new RuntimeException("Connection timed out. Check if the host is reachable.");
        }
        return "# probe: failed\n" + lastOutput;
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
