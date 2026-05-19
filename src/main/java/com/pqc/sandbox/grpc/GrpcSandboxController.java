package com.pqc.sandbox.grpc;

import com.pqc.common.QudoCryptoService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.MessageDigest;
import java.util.*;

/**
 * gRPC service sandbox — REST stand-in.
 *
 * <p>The legacy gRPC service used Protobuf + grpc-netty on a separate port (8091)
 * to demonstrate PQC-signed unary calls and KEM-based key exchange. Adding a
 * gRPC transport to the single Spring Boot app would mean pulling in
 * grpc-netty / grpc-stub / protobuf compiler — heavy infra for one demo.</p>
 *
 * <p>This REST shim exposes the same RPC operations (signData / verifySignature
 * / exchangeKeys / listAlgorithms) under {@code /api/v1/sandbox/grpc/*} so the
 * PQC flow is fully exercisable through the sandbox console. Every response
 * includes a {@code wireProtocol} marker noting that production uses gRPC
 * unary calls over HTTP/2 with the same payload shapes.</p>
 */
@RestController
@RequestMapping("/api/v1/sandbox/grpc")
public class GrpcSandboxController {

    private final QudoCryptoService qudo;

    public GrpcSandboxController(QudoCryptoService qudo) { this.qudo = qudo; }

    @PostMapping("/sign-data")
    public ResponseEntity<?> signData(@RequestBody Map<String, String> req) {
        try {
            String algorithm = req.getOrDefault("algorithm", "ML-DSA-65");
            byte[] data = Base64.getDecoder().decode(req.get("data"));
            long start = System.nanoTime();
            QudoCryptoService.KeyMaterial keys = qudo.generateKeyPair(algorithm);
            byte[] sig = qudo.sign(data, keys.privateKeyPem(), algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "signature", Base64.getEncoder().encodeToString(sig),
                    "publicKey", keys.publicKeyBase64(),
                    "algorithm", algorithm,
                    "latencyMs", elapsed,
                    "wireProtocol", "REST stand-in (production: gRPC unary call PqcService/SignData)"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/verify-signature")
    public ResponseEntity<?> verifySignature(@RequestBody Map<String, String> req) {
        try {
            String algorithm = req.getOrDefault("algorithm", "ML-DSA-65");
            byte[] data = Base64.getDecoder().decode(req.get("data"));
            byte[] sig = Base64.getDecoder().decode(req.get("signature"));
            byte[] pubKey = Base64.getDecoder().decode(req.get("publicKey"));
            long start = System.nanoTime();
            boolean valid = qudo.verify(data, sig, pubKey, algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "valid", valid,
                    "algorithm", algorithm,
                    "latencyMs", elapsed,
                    "wireProtocol", "REST stand-in (production: gRPC unary call PqcService/VerifySignature)"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/exchange-keys")
    public ResponseEntity<?> exchangeKeys(@RequestBody Map<String, String> req) {
        try {
            String algorithm = req.getOrDefault("algorithm", "ML-KEM-768");
            long start = System.nanoTime();
            // Responder generates its KEM keypair and encapsulates against the
            // initiator's public key. Returns ciphertext + a shared-secret
            // fingerprint (we don't return the secret bytes themselves over the
            // wire — that's the whole point of KEM encapsulation).
            QudoCryptoService.KeyMaterial responderKeys = qudo.generateKeyPair(algorithm);
            String initiatorPub = req.get("initiatorPublicKey");
            byte[] kemCiphertext;
            byte[] sharedSecret;
            if (initiatorPub != null && !initiatorPub.isBlank()) {
                QudoCryptoService.KemEncapsulation encap = qudo.kemEncapsulate(
                        Base64.getDecoder().decode(initiatorPub), algorithm);
                kemCiphertext = encap.ciphertext();
                sharedSecret = encap.sharedSecret();
            } else {
                // No initiator key supplied — encapsulate against our own as a self-test
                QudoCryptoService.KemEncapsulation encap = qudo.kemEncapsulate(
                        responderKeys.publicKeyPem(), algorithm);
                kemCiphertext = encap.ciphertext();
                sharedSecret = encap.sharedSecret();
            }
            byte[] secretFingerprint = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
            long elapsed = (System.nanoTime() - start) / 1_000_000;

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "responderPublicKey", responderKeys.publicKeyBase64(),
                    "kemCiphertext", Base64.getEncoder().encodeToString(kemCiphertext),
                    "sharedSecretSha256", Base64.getEncoder().encodeToString(secretFingerprint),
                    "kemCiphertextBytes", kemCiphertext.length,
                    "algorithm", algorithm,
                    "latencyMs", elapsed,
                    "wireProtocol", "REST stand-in (production: gRPC unary call PqcService/ExchangeKeys)",
                    "note", "Shared secret bytes are intentionally not returned over the wire — only their SHA-256 fingerprint. Decapsulate locally with your private key to derive the same secret."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @GetMapping("/algorithms")
    public ResponseEntity<?> listAlgorithms() {
        List<Map<String, Object>> details = List.of(
                Map.of("name", "ML-DSA-44", "category", "SIGNATURE", "fipsStandard", "FIPS 204", "securityLevel", 2),
                Map.of("name", "ML-DSA-65", "category", "SIGNATURE", "fipsStandard", "FIPS 204", "securityLevel", 3),
                Map.of("name", "ML-DSA-87", "category", "SIGNATURE", "fipsStandard", "FIPS 204", "securityLevel", 5),
                Map.of("name", "SLH-DSA-SHA2-128s", "category", "SIGNATURE", "fipsStandard", "FIPS 205", "securityLevel", 1),
                Map.of("name", "ML-KEM-512", "category", "KEM", "fipsStandard", "FIPS 203", "securityLevel", 1),
                Map.of("name", "ML-KEM-768", "category", "KEM", "fipsStandard", "FIPS 203", "securityLevel", 3),
                Map.of("name", "ML-KEM-1024", "category", "KEM", "fipsStandard", "FIPS 203", "securityLevel", 5)
        );
        return ResponseEntity.ok(Map.of(
                "algorithms", details,
                "wireProtocol", "REST stand-in (production: gRPC unary call PqcService/ListAlgorithms)"));
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "grpc-sandbox",
                "wireProtocol", "REST stand-in",
                "productionTransport", "gRPC over HTTP/2 (with TLS 1.3 X25519MLKEM768 hybrid handshake)",
                "note", "The legacy grpc-service runs an actual gRPC server with PQC JWT interceptor and the same PQC payload shapes. This sandbox exposes those operations as REST so they can be exercised without embedding a gRPC transport in the single Spring Boot BE."));
    }
}
