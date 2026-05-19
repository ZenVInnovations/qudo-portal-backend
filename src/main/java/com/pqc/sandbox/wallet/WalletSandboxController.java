package com.pqc.sandbox.wallet;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/api/v1/sandbox/wallet")
public class WalletSandboxController {
    private final WalletService walletService;
    public WalletSandboxController(WalletService walletService) { this.walletService = walletService; }

    @PostMapping("/create")
    public ResponseEntity<?> createWallet(@RequestBody Map<String, String> req) {
        try {
            long start = System.nanoTime();
            var w = walletService.createWallet(req.getOrDefault("name", "My Wallet"), req.get("algorithm"));
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            String pubKey = walletService.getPublicKey(w.id());
            return ResponseEntity.ok(Map.of("status", "success", "walletId", w.id(), "name", w.name(),
                    "address", w.address(), "algorithm", w.algorithm(),
                    "publicKey", pubKey != null ? pubKey : "", "latencyMs", elapsed));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getWallet(@PathVariable String id) {
        var w = walletService.getWallet(id);
        if (w == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(Map.of("walletId", w.id(), "name", w.name(), "address", w.address(),
                "algorithm", w.algorithm(), "createdAt", w.createdAt().toString()));
    }

    @PostMapping("/{id}/sign-transaction")
    public ResponseEntity<?> signTransaction(@PathVariable String id, @RequestBody Map<String, String> req) {
        try {
            long start = System.nanoTime();
            Map<String, Object> result = walletService.signTransaction(id, req.getOrDefault("data", "tx-data"));
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of("status", "success", "result", result, "latencyMs", elapsed));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @PostMapping("/verify-transaction")
    public ResponseEntity<?> verifyTransaction(@RequestBody Map<String, String> req) {
        try {
            long start = System.nanoTime();
            String data = req.get("data"), sig = req.get("signature"), pub = req.get("publicKey");
            if (data == null || sig == null || pub == null)
                return ResponseEntity.badRequest().body(Map.of("status","error","message","Required fields: data, signature, publicKey"));
            boolean valid = walletService.verifyTransaction(data, sig, pub, req.getOrDefault("algorithm", "ML-DSA-65"));
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return ResponseEntity.ok(Map.of("status", "success", "valid", valid, "latencyMs", elapsed));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage())); }
    }

    @GetMapping("/list")
    public ResponseEntity<?> listWallets() {
        List<Map<String, String>> list = new ArrayList<>();
        walletService.listWallets().forEach(w -> list.add(Map.of("id", w.id(), "name", w.name(), "address", w.address(), "algorithm", w.algorithm())));
        return ResponseEntity.ok(Map.of("wallets", list, "count", list.size()));
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "wallet-sandbox", "walletCount", walletService.listWallets().size()));
    }
}
