package com.pqc.sandbox.exchange;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sandbox/exchange")
public class ExchangeSandboxController {
    private final ExchangeService svc;
    public ExchangeSandboxController(ExchangeService svc) { this.svc = svc; }

    @PostMapping("/create-custody-wallet")
    public ResponseEntity<?> create(@RequestBody Map<String, String> req) {
        try { long s=System.nanoTime(); var r=svc.createCustodyWallet(req.getOrDefault("name","Custody"));
            return ResponseEntity.ok(Map.of("status","success","result",r,"latencyMs",(System.nanoTime()-s)/1_000_000)); }
        catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }
    @PostMapping("/deposit")
    public ResponseEntity<?> deposit(@RequestBody Map<String, String> req) {
        try { String wid=req.get("walletId"); if(wid==null) return ResponseEntity.badRequest().body(Map.of("status","error","message","'walletId' is required"));
            var r=svc.deposit(wid,req.getOrDefault("amount","0"),req.getOrDefault("asset","BTC"));
            return ResponseEntity.ok(Map.of("status","success","result",r)); }
        catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }
    @PostMapping("/withdraw")
    public ResponseEntity<?> withdraw(@RequestBody Map<String, String> req) {
        try { String wid=req.get("walletId"); if(wid==null) return ResponseEntity.badRequest().body(Map.of("status","error","message","'walletId' is required"));
            var r=svc.withdraw(wid,req.getOrDefault("amount","0"),req.getOrDefault("asset","BTC"));
            return ResponseEntity.ok(Map.of("status","success","result",r)); }
        catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }
    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@RequestBody Map<String, String> req) {
        try { String from=req.get("fromWalletId"),to=req.get("toWalletId");
            if(from==null||to==null) return ResponseEntity.badRequest().body(Map.of("status","error","message","'fromWalletId' and 'toWalletId' are required"));
            var r=svc.transfer(from,to,req.getOrDefault("amount","0"));
            return ResponseEntity.ok(Map.of("status","success","result",r)); }
        catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }
    @GetMapping("/wallets") public ResponseEntity<?> wallets() { return ResponseEntity.ok(Map.of("wallets",svc.listWallets())); }
    @GetMapping("/transactions") public ResponseEntity<?> txs() { return ResponseEntity.ok(Map.of("transactions",svc.listTransactions())); }
    @GetMapping("/health") public ResponseEntity<?> health() { return ResponseEntity.ok(Map.of("status","UP","service","exchange-sandbox")); }
}
