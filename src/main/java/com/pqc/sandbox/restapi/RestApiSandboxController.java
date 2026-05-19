package com.pqc.sandbox.restapi;

import com.pqc.common.QudoCryptoService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REST API + PQC JWT sandbox. Demonstrates the asymmetric-JWT pattern: issue a
 * token signed with ML-DSA-65, verify it with the published public key, and
 * call a Bearer-protected endpoint.
 *
 * <p>Spring Security is intentionally not enabled in the new BE (Google OAuth2
 * is deferred), so {@code /secure} parses the {@code Authorization} header
 * manually via {@link PqcJwtProvider#validateToken(String)} instead of relying
 * on a SecurityFilterChain.</p>
 */
@RestController
@RequestMapping("/api/v1/sandbox/rest-api")
public class RestApiSandboxController {

    private final PqcJwtProvider jwt;
    private final QudoCryptoService qudo;

    public RestApiSandboxController(PqcJwtProvider jwt, QudoCryptoService qudo) {
        this.jwt = jwt;
        this.qudo = qudo;
    }

    // ===== Auth =====

    @PostMapping("/auth/token")
    public ResponseEntity<?> getToken(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        // Demo credential check — admin/admin. NOT a production auth pattern,
        // see the migration docs for OIDC/SAML-backed flows.
        if ("admin".equals(username) && "admin".equals(password)) {
            try {
                return ResponseEntity.ok(jwt.generateToken(username));
            } catch (Exception e) {
                return ResponseEntity.status(500).body(Map.of("error", "Token generation failed", "message", e.getMessage()));
            }
        }
        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials", "hint", "Use admin/admin for the sandbox demo."));
    }

    @PostMapping("/auth/verify")
    public ResponseEntity<?> verifyToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Token is required"));
        }
        try {
            return ResponseEntity.ok(jwt.verifyToken(token));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Verification failed", "message", e.getMessage()));
        }
    }

    @GetMapping("/auth/jwks")
    public ResponseEntity<?> getJwks() {
        return ResponseEntity.ok(jwt.getPublicKeyInfo());
    }

    // ===== API =====

    @GetMapping("/hello")
    public ResponseEntity<?> hello() {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("message", "Hello from the Qudo PQC sandbox");
        resp.put("timestamp", Instant.now().toString());
        resp.put("transport", "TLS 1.3 with X25519MLKEM768 hybrid key exchange (when accessed via a PQC-aware reverse proxy)");
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/secure")
    public ResponseEntity<?> secure(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        String user = "anonymous";
        boolean authenticated = false;
        String reason = "No Authorization header. Send 'Authorization: Bearer <token>'.";
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwt.validateToken(token)) {
                user = jwt.getUsernameFromToken(token);
                authenticated = true;
                reason = "ML-DSA-65 signature verified by Qudo JNI provider.";
            } else {
                reason = "Token signature failed verification.";
            }
        }
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", authenticated ? "success" : "unauthorized");
        resp.put("message", authenticated ? "Quantum-safe authenticated endpoint" : "Authentication required");
        resp.put("user", user);
        resp.put("authentication", "JWT signed with ML-DSA-65 (FIPS 204) via Qudo provider");
        resp.put("transport", "TLS 1.3 with X25519MLKEM768 hybrid key exchange");
        resp.put("note", reason);
        resp.put("timestamp", Instant.now().toString());
        return authenticated ? ResponseEntity.ok(resp) : ResponseEntity.status(401).body(resp);
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        boolean pqcAvailable;
        try {
            qudo.generateKeyPair("ML-DSA-44");
            pqcAvailable = true;
        } catch (Exception e) {
            pqcAvailable = false;
        }
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "UP");
        resp.put("service", "rest-api-sandbox");
        resp.put("pqcProvider", pqcAvailable ? "Qudo FIPS (active)" : "unavailable");
        resp.put("keyExchange", "X25519MLKEM768 (via PQC-aware reverse proxy)");
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/crypto-info")
    public ResponseEntity<?> cryptoInfo() {
        List<String> algos = qudo.getSupportedAlgorithms();
        List<Map<String, String>> pqcList = algos.stream().map(a -> Map.of(
                "algorithm", a,
                "type", a.startsWith("ML-KEM") ? "KEM" : "Signature",
                "provider", "Qudo FIPS"
        )).toList();
        return ResponseEntity.ok(Map.of("pqcAlgorithms", pqcList, "provider", "Qudo FIPS", "totalPqcAlgorithms", pqcList.size()));
    }
}
