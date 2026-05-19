package com.pqc.sandbox.signing;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sandbox/signing")
public class SigningSandboxController {

    private final SigningService signingService;

    public SigningSandboxController(SigningService signingService) { this.signingService = signingService; }

    @PostMapping("/sign")
    public ResponseEntity<?> signData(@RequestBody Map<String, String> request) {
        try {
            String algorithm = request.getOrDefault("algorithm", "ML-DSA-65");
            byte[] data = Base64.getDecoder().decode(request.get("data"));
            long start = System.nanoTime();
            Map<String, String> result = signingService.sign(data, algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "signature", result.get("signature"),
                    "publicKey", result.get("publicKey"),
                    "algorithm", result.get("algorithm"),
                    "dataHash", result.get("dataHash"),
                    "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifySignature(@RequestBody Map<String, String> request) {
        try {
            String algorithm = request.getOrDefault("algorithm", "ML-DSA-65");
            byte[] data = Base64.getDecoder().decode(request.get("data"));
            byte[] signature = Base64.getDecoder().decode(request.get("signature"));
            byte[] publicKey = Base64.getDecoder().decode(request.get("publicKey"));
            long start = System.nanoTime();
            Map<String, Object> result = signingService.verify(data, signature, publicKey, algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "valid", result.get("valid"),
                    "algorithm", result.get("algorithm"),
                    "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/sign-container")
    public ResponseEntity<?> signContainer(@RequestBody Map<String, String> request) {
        try {
            String imageDigest = request.get("imageDigest");
            String algorithm = request.getOrDefault("algorithm", "ML-DSA-65");
            long start = System.nanoTime();
            Map<String, String> result = signingService.signContainer(imageDigest, algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of("status", "success", "result", result, "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @GetMapping("/algorithms")
    public ResponseEntity<?> getAlgorithms() {
        List<String> algorithms = signingService.getSupportedAlgorithms();
        return ResponseEntity.ok(Map.of(
                "algorithms", algorithms,
                "supported", Map.of(
                        "ML-DSA-44", Map.of("fips", "FIPS 204", "securityLevel", "NIST Level 2", "signatureBytes", 2420, "publicKeyBytes", 1860, "use", "Lightweight signing, IoT"),
                        "ML-DSA-65", Map.of("fips", "FIPS 204", "securityLevel", "NIST Level 3", "signatureBytes", 3309, "publicKeyBytes", 2726, "use", "General purpose (recommended)"),
                        "ML-DSA-87", Map.of("fips", "FIPS 204", "securityLevel", "NIST Level 5", "signatureBytes", 4627, "publicKeyBytes", 3595, "use", "Highest security")),
                "note", "SLH-DSA (FIPS 205) is available for certificate signing via the CA sandbox. Data signing uses ML-DSA only.",
                "provider", "Qudo FIPS Provider v1.0.0"));
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "signing-sandbox",
                "pqcAlgorithms", signingService.getSupportedAlgorithms()));
    }
}
