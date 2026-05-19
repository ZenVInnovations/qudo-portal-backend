package com.pqc.sandbox.kms;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sandbox/kms")
public class KmsSandboxController {

    private final KmsService kms;
    private final Pkcs11SimulatorService pkcs11;

    public KmsSandboxController(KmsService kms, Pkcs11SimulatorService pkcs11) {
        this.kms = kms;
        this.pkcs11 = pkcs11;
    }

    @PostMapping("/create-key")
    public ResponseEntity<?> createKey(@RequestBody Map<String, String> req) {
        try {
            long s = System.nanoTime();
            var r = kms.createKey(req.getOrDefault("alias", "key"), req.get("algorithm"), req.get("usage"));
            return ResponseEntity.ok(Map.of("status", "success", "result", r, "latencyMs", (System.nanoTime() - s) / 1_000_000));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @GetMapping("/key/{keyId}")
    public ResponseEntity<?> getKey(@PathVariable String keyId) {
        try { return ResponseEntity.ok(kms.getKeyMetadata(keyId)); }
        catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @PostMapping("/sign")
    public ResponseEntity<?> sign(@RequestBody Map<String, String> req) {
        try {
            byte[] data = Base64.getDecoder().decode(req.get("data"));
            long s = System.nanoTime();
            var r = kms.sign(req.get("keyId"), data);
            return ResponseEntity.ok(Map.of("status", "success", "result", r, "latencyMs", (System.nanoTime() - s) / 1_000_000));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> req) {
        try {
            byte[] data = Base64.getDecoder().decode(req.get("data"));
            byte[] sig = Base64.getDecoder().decode(req.get("signature"));
            var r = kms.verify(req.get("keyId"), data, sig);
            return ResponseEntity.ok(Map.of("status", "success", "result", r));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @PostMapping("/rotate-key")
    public ResponseEntity<?> rotate(@RequestBody Map<String, String> req) {
        try {
            var r = kms.rotateKey(req.get("keyId"));
            return ResponseEntity.ok(Map.of("status", "success", "newKey", r));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @DeleteMapping("/key/{keyId}")
    public ResponseEntity<?> destroy(@PathVariable String keyId) {
        try {
            kms.destroyKey(keyId);
            return ResponseEntity.ok(Map.of("status", "success", "keyId", keyId, "newStatus", "DESTROYED"));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @GetMapping("/keys") public ResponseEntity<?> list() { return ResponseEntity.ok(Map.of("keys", kms.listKeys())); }

    @GetMapping("/audit")
    public ResponseEntity<?> audit(@RequestParam(required = false) String keyId) {
        return ResponseEntity.ok(Map.of("auditLog", kms.getAuditLog(keyId)));
    }

    @GetMapping("/audit/{keyId}")
    public ResponseEntity<?> auditByKey(@PathVariable String keyId) {
        return ResponseEntity.ok(Map.of("auditLog", kms.getAuditLog(keyId)));
    }

    @PostMapping("/pkcs11/init")
    public ResponseEntity<?> pkcs11Init(@RequestBody Map<String, String> req) {
        try { return ResponseEntity.ok(Map.of("status", "success", "result", pkcs11.initToken(req.get("label"), req.get("pin")))); }
        catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @PostMapping("/pkcs11/store")
    public ResponseEntity<?> pkcs11Store(@RequestBody Map<String, String> req) {
        try { return ResponseEntity.ok(Map.of("status", "success", "result", pkcs11.storeKey(req.get("label"), req.get("keyId")))); }
        catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @PostMapping("/pkcs11/retrieve")
    public ResponseEntity<?> pkcs11Retrieve(@RequestBody Map<String, String> req) {
        try { return ResponseEntity.ok(Map.of("status", "success", "result", pkcs11.retrieveKey(req.get("label"), req.get("keyId")))); }
        catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "kms-sandbox", "activeKeys", kms.listKeys().size()));
    }
}
