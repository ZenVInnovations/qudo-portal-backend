package com.pqc.sandbox.defi;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sandbox/defi")
public class DefiSandboxController {
    private final DefiService svc;
    public DefiSandboxController(DefiService svc) { this.svc = svc; }

    @PostMapping("/create-multisig")
    public ResponseEntity<?> create(@RequestBody Map<String,Object> req) {
        try { long s=System.nanoTime(); var r=svc.createMultiSigWallet(
                (String)req.getOrDefault("name","MultiSig"),
                ((Number)req.getOrDefault("signerCount",3)).intValue(),
                ((Number)req.getOrDefault("threshold",2)).intValue());
            return ResponseEntity.ok(Map.of("status","success","result",r,"latencyMs",(System.nanoTime()-s)/1_000_000)); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @PostMapping("/create-proposal")
    public ResponseEntity<?> propose(@RequestBody Map<String,String> req) {
        try { String wid=req.get("walletId");
            if(wid==null) return ResponseEntity.badRequest().body(Map.of("status","error","message","'walletId' is required"));
            var r=svc.createProposal(wid,req.getOrDefault("description",""),req.getOrDefault("data","proposal-data"));
            return ResponseEntity.ok(Map.of("status","success","result",r)); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @PostMapping("/sign-proposal")
    public ResponseEntity<?> sign(@RequestBody Map<String,Object> req) {
        try { String pid=(String)req.get("proposalId");
            if(pid==null) return ResponseEntity.badRequest().body(Map.of("status","error","message","'proposalId' is required"));
            var r=svc.signProposal(pid,((Number)req.getOrDefault("signerIndex",0)).intValue());
            return ResponseEntity.ok(Map.of("status","success","result",r)); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @PostMapping("/execute-proposal")
    public ResponseEntity<?> execute(@RequestBody Map<String,String> req) {
        try { String pid=req.get("proposalId");
            if(pid==null) return ResponseEntity.badRequest().body(Map.of("status","error","message","'proposalId' is required"));
            var r=svc.executeProposal(pid);
            return ResponseEntity.ok(Map.of("status","success","result",r)); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @GetMapping("/wallets") public ResponseEntity<?> wallets() { return ResponseEntity.ok(Map.of("wallets",svc.listWallets())); }
    @GetMapping("/proposals") public ResponseEntity<?> proposals() { return ResponseEntity.ok(Map.of("proposals",svc.listProposals())); }
    @GetMapping("/health") public ResponseEntity<?> health() { return ResponseEntity.ok(Map.of("status","UP","service","defi-sandbox")); }
}
