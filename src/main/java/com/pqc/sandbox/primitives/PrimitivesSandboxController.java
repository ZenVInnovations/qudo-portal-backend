package com.pqc.sandbox.primitives;

import com.pqc.common.QudoCryptoService;
import com.pqc.common.QudoCryptoService.KeyMaterial;
import com.pqc.common.QudoCryptoService.KemEncapsulation;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/**
 * PQC primitives sandbox. The single interactive surface an engineer touches
 * to understand the bare crypto operations Qudo exposes: keygen, sign / verify,
 * KEM encapsulate / decapsulate, hash, AES-GCM, address derivation.
 *
 * <p>Use-case demos (JWT, S/MIME, multi-sig, VPN, CA hierarchy) are not part
 * of this sandbox — they're documented separately in the migration guides
 * because they're just specific compositions of the operations below.</p>
 */
@RestController
@RequestMapping("/api/v1/sandbox/primitives")
public class PrimitivesSandboxController {

    private static final SecureRandom RNG = new SecureRandom();

    private final QudoCryptoService qudo;

    public PrimitivesSandboxController(QudoCryptoService qudo) { this.qudo = qudo; }

    /**
     * Pull a required base64-encoded field out of the request body, returning a
     * customer-friendly error if it's missing or malformed. Replaces the raw
     * {@code Base64.getDecoder().decode(req.get("x"))} which NPEs into an ugly
     * stacktrace message when the field is absent.
     */
    private static byte[] requireBase64(Map<String, String> req, String field) {
        String v = req.get(field);
        if (v == null || v.isEmpty()) {
            throw new IllegalArgumentException("'" + field + "' is required.");
        }
        try {
            return Base64.getDecoder().decode(v);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("'" + field + "' must be valid base64.");
        }
    }

    // ───── Keygen ─────

    @PostMapping("/keygen")
    public ResponseEntity<?> generateKeyPair(@RequestBody Map<String, String> req) {
        try {
            String algorithm = req.getOrDefault("algorithm", "ML-DSA-65");
            long start = System.nanoTime();
            KeyMaterial keys = qudo.generateKeyPair(algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "algorithm", algorithm,
                    "publicKey", keys.publicKeyBase64(),
                    "privateKey", keys.privateKeyBase64(),
                    "publicKeyBytes", keys.publicKeyPem().length,
                    "privateKeyBytes", keys.privateKeyPem().length,
                    "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ───── Sign / Verify (ML-DSA + SLH-DSA) ─────

    @PostMapping("/sign")
    public ResponseEntity<?> sign(@RequestBody Map<String, String> req) {
        try {
            String algorithm = req.getOrDefault("algorithm", "ML-DSA-65");
            byte[] data = requireBase64(req, "data");
            byte[] privateKey = requireBase64(req, "privateKey");
            long start = System.nanoTime();
            byte[] sig = qudo.sign(data, privateKey, algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "algorithm", algorithm,
                    "signature", Base64.getEncoder().encodeToString(sig),
                    "signatureBytes", sig.length,
                    "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> req) {
        try {
            String algorithm = req.getOrDefault("algorithm", "ML-DSA-65");
            byte[] data = requireBase64(req, "data");
            byte[] signature = requireBase64(req, "signature");
            byte[] publicKey = requireBase64(req, "publicKey");
            long start = System.nanoTime();
            boolean valid = qudo.verify(data, signature, publicKey, algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "valid", valid,
                    "algorithm", algorithm,
                    "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ───── KEM Encapsulate / Decapsulate (ML-KEM) ─────

    @PostMapping("/kem-encapsulate")
    public ResponseEntity<?> kemEncapsulate(@RequestBody Map<String, String> req) {
        try {
            String algorithm = req.getOrDefault("algorithm", "ML-KEM-768");
            byte[] publicKey = requireBase64(req, "publicKey");
            long start = System.nanoTime();
            KemEncapsulation encap = qudo.kemEncapsulate(publicKey, algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "algorithm", algorithm,
                    "ciphertext", Base64.getEncoder().encodeToString(encap.ciphertext()),
                    "sharedSecret", Base64.getEncoder().encodeToString(encap.sharedSecret()),
                    "ciphertextBytes", encap.ciphertext().length,
                    "sharedSecretBytes", encap.sharedSecret().length,
                    "latencyMs", elapsed,
                    "note", "In production the sender keeps the shared secret + sends only the ciphertext over the wire. The recipient decapsulates with their private key to derive the same shared secret."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/kem-decapsulate")
    public ResponseEntity<?> kemDecapsulate(@RequestBody Map<String, String> req) {
        try {
            String algorithm = req.getOrDefault("algorithm", "ML-KEM-768");
            byte[] ciphertext = requireBase64(req, "ciphertext");
            byte[] privateKey = requireBase64(req, "privateKey");
            long start = System.nanoTime();
            byte[] sharedSecret = qudo.kemDecapsulate(ciphertext, privateKey, algorithm);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "algorithm", algorithm,
                    "sharedSecret", Base64.getEncoder().encodeToString(sharedSecret),
                    "sharedSecretBytes", sharedSecret.length,
                    "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ───── Hashing ─────

    @PostMapping("/hash")
    public ResponseEntity<?> hash(@RequestBody Map<String, String> req) {
        try {
            String algorithm = req.getOrDefault("algorithm", "SHA-256");
            byte[] data = requireBase64(req, "data");
            long start = System.nanoTime();
            byte[] digest;
            if ("SHA-256".equalsIgnoreCase(algorithm)) {
                digest = qudo.sha256(data);
            } else {
                // SHA-384 / SHA-512 via stock java.security
                digest = MessageDigest.getInstance(algorithm).digest(data);
            }
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "algorithm", algorithm,
                    "digest", Base64.getEncoder().encodeToString(digest),
                    "digestBytes", digest.length,
                    "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ───── AES-256-GCM (commonly paired with ML-KEM) ─────

    @PostMapping("/aes-gcm-encrypt")
    public ResponseEntity<?> aesEncrypt(@RequestBody Map<String, String> req) {
        try {
            byte[] plaintext = requireBase64(req, "plaintext");
            byte[] key = requireBase64(req, "key");
            if (key.length != 32) {
                return ResponseEntity.badRequest().body(Map.of(
                        "status", "error",
                        "message", "AES-256 requires a 32-byte key; got " + key.length + " bytes"));
            }
            byte[] iv = new byte[12];
            RNG.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            long start = System.nanoTime();
            byte[] ciphertext = c.doFinal(plaintext);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "cipher", "AES-256-GCM",
                    "ciphertext", Base64.getEncoder().encodeToString(ciphertext),
                    "iv", Base64.getEncoder().encodeToString(iv),
                    "ciphertextBytes", ciphertext.length,
                    "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/aes-gcm-decrypt")
    public ResponseEntity<?> aesDecrypt(@RequestBody Map<String, String> req) {
        try {
            byte[] ciphertext = requireBase64(req, "ciphertext");
            byte[] key = requireBase64(req, "key");
            byte[] iv = requireBase64(req, "iv");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            long start = System.nanoTime();
            byte[] plaintext = c.doFinal(ciphertext);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "cipher", "AES-256-GCM",
                    "plaintext", Base64.getEncoder().encodeToString(plaintext),
                    "plaintextBytes", plaintext.length,
                    "latencyMs", elapsed));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ───── Address derivation (blockchain-style) ─────

    @PostMapping("/derive-address")
    public ResponseEntity<?> deriveAddress(@RequestBody Map<String, String> req) {
        try {
            byte[] publicKey = requireBase64(req, "publicKey");
            String address = qudo.deriveAddress(publicKey);
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "address", address,
                    "note", "First 20 bytes of SHA-256(publicKey), 0x-prefixed (Ethereum-style address shape)."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ───── Catalog ─────

    @GetMapping("/algorithms")
    public ResponseEntity<?> listAlgorithms() {
        return ResponseEntity.ok(Map.of(
                "signing", List.of(
                        Map.of("name", "ML-DSA-44", "fips", "FIPS 204", "level", 2),
                        Map.of("name", "ML-DSA-65", "fips", "FIPS 204", "level", 3),
                        Map.of("name", "ML-DSA-87", "fips", "FIPS 204", "level", 5),
                        Map.of("name", "SLH-DSA-SHA2-128s", "fips", "FIPS 205", "level", 1),
                        Map.of("name", "SLH-DSA-SHA2-128f", "fips", "FIPS 205", "level", 1),
                        Map.of("name", "SLH-DSA-SHA2-256s", "fips", "FIPS 205", "level", 5),
                        Map.of("name", "SLH-DSA-SHA2-256f", "fips", "FIPS 205", "level", 5)),
                "kem", List.of(
                        Map.of("name", "ML-KEM-512", "fips", "FIPS 203", "level", 1),
                        Map.of("name", "ML-KEM-768", "fips", "FIPS 203", "level", 3),
                        Map.of("name", "ML-KEM-1024", "fips", "FIPS 203", "level", 5)),
                "hashing", List.of("SHA-256", "SHA-384", "SHA-512"),
                "symmetric", List.of("AES-256-GCM")));
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "primitives-sandbox",
                "provider", "Qudo FIPS Provider (JNI)"));
    }
}
