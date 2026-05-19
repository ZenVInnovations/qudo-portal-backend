package com.pqc.sandbox.email;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST surface for the PQC email encryption sandbox. Uses ML-KEM (FIPS 203)
 * for key establishment, ML-DSA (FIPS 204) for sender auth, and AES-256-GCM
 * for symmetric encryption.
 */
@RestController
@RequestMapping("/api/v1/sandbox/email")
public class EmailSandboxController {

    private final EmailCryptoService emailCryptoService;

    public EmailSandboxController(EmailCryptoService emailCryptoService) {
        this.emailCryptoService = emailCryptoService;
    }

    @PostMapping("/register-keys")
    public ResponseEntity<?> registerKeys(@RequestBody Map<String, String> request) {
        try {
            long start = System.nanoTime();
            String id = request.get("id");
            String type = request.getOrDefault("type", "recipient");
            String algorithm = request.get("algorithm");
            Map<String, String> result = "sender".equalsIgnoreCase(type)
                    ? emailCryptoService.registerSenderKeys(id, algorithm)
                    : emailCryptoService.registerRecipientKeys(id, algorithm);
            return ok(result, start);
        } catch (IllegalArgumentException e) { return badRequest(e.getMessage()); }
        catch (Exception e) { return serverError(e.getMessage()); }
    }

    @GetMapping("/keys/{recipientId}")
    public ResponseEntity<?> getPublicKey(@PathVariable String recipientId) {
        try {
            long start = System.nanoTime();
            return ok(emailCryptoService.getRecipientPublicKey(recipientId), start);
        } catch (IllegalArgumentException e) { return badRequest(e.getMessage()); }
        catch (Exception e) { return serverError(e.getMessage()); }
    }

    @GetMapping("/keys")
    public ResponseEntity<?> listKeys() {
        try {
            long start = System.nanoTime();
            return ok(emailCryptoService.listKeys(), start);
        } catch (Exception e) { return serverError(e.getMessage()); }
    }

    @PostMapping("/encrypt")
    public ResponseEntity<?> encrypt(@RequestBody Map<String, String> request) {
        try {
            long start = System.nanoTime();
            return ok(emailCryptoService.encryptMessage(
                    request.get("message"),
                    request.getOrDefault("recipientId", "default-recipient"),
                    request.get("algorithm")), start);
        } catch (IllegalArgumentException e) { return badRequest(e.getMessage()); }
        catch (Exception e) { return serverError(e.getMessage()); }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<?> decrypt(@RequestBody Map<String, String> request) {
        try {
            long start = System.nanoTime();
            return ok(emailCryptoService.decryptMessage(
                    request.get("ciphertext"),
                    request.get("encapsulatedKey"),
                    request.get("iv"),
                    request.getOrDefault("recipientId", "default-recipient")), start);
        } catch (IllegalArgumentException e) { return badRequest(e.getMessage()); }
        catch (Exception e) { return serverError(e.getMessage()); }
    }

    @PostMapping("/sign")
    public ResponseEntity<?> sign(@RequestBody Map<String, String> request) {
        try {
            long start = System.nanoTime();
            return ok(emailCryptoService.signMessage(
                    request.get("message"),
                    request.getOrDefault("senderId", "default-sender"),
                    request.get("algorithm")), start);
        } catch (IllegalArgumentException e) { return badRequest(e.getMessage()); }
        catch (Exception e) { return serverError(e.getMessage()); }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> request) {
        try {
            long start = System.nanoTime();
            return ok(emailCryptoService.verifyMessage(
                    request.get("message"),
                    request.get("signature"),
                    request.get("publicKey"),
                    request.get("algorithm")), start);
        } catch (IllegalArgumentException e) { return badRequest(e.getMessage()); }
        catch (Exception e) { return serverError(e.getMessage()); }
    }

    @PostMapping("/send-secure")
    public ResponseEntity<?> sendSecure(@RequestBody Map<String, String> request) {
        try {
            long start = System.nanoTime();
            return ok(emailCryptoService.sendSecureEmail(
                    request.get("message"),
                    request.getOrDefault("senderId", "default-sender"),
                    request.getOrDefault("recipientId", "default-recipient"),
                    request.get("kemAlgorithm"),
                    request.get("sigAlgorithm")), start);
        } catch (IllegalArgumentException e) { return badRequest(e.getMessage()); }
        catch (Exception e) { return serverError(e.getMessage()); }
    }

    @PostMapping("/receive-secure")
    public ResponseEntity<?> receiveSecure(@RequestBody Map<String, String> request) {
        try {
            long start = System.nanoTime();
            return ok(emailCryptoService.receiveSecureEmail(
                    request.get("ciphertext"),
                    request.get("encapsulatedKey"),
                    request.get("iv"),
                    request.getOrDefault("recipientId", "default-recipient")), start);
        } catch (IllegalArgumentException e) { return badRequest(e.getMessage()); }
        catch (Exception e) { return serverError(e.getMessage()); }
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP", "service", "email-sandbox",
                "provider", "Qudo FIPS v1.0.0",
                "algorithms", Map.of(
                        "encryption", "ML-KEM-512 / 768 (default) / 1024 + AES-256-GCM",
                        "signature", "ML-DSA-44 / 65 (default) / 87")));
    }

    private ResponseEntity<?> ok(Map<String, ?> result, long startNanos) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "success");
        body.put("latencyMs", (System.nanoTime() - startNanos) / 1_000_000);
        body.put("result", result);
        return ResponseEntity.ok(body);
    }

    private ResponseEntity<?> badRequest(String message) {
        return ResponseEntity.badRequest().body(Map.of("status", "error", "error", message));
    }

    private ResponseEntity<?> serverError(String message) {
        return ResponseEntity.internalServerError().body(Map.of("status", "error", "error", message));
    }
}
