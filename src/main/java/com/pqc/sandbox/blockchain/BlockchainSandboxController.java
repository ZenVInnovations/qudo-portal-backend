package com.pqc.sandbox.blockchain;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sandbox/blockchain")
public class BlockchainSandboxController {
    private final BlockchainService svc;
    public BlockchainSandboxController(BlockchainService svc) { this.svc = svc; }

    @PostMapping("/register-node")
    public ResponseEntity<?> register(@RequestBody Map<String,String> req) {
        try { long s=System.nanoTime(); var r=svc.registerNode(req.getOrDefault("name","Validator"));
            return ResponseEntity.ok(Map.of("status","success","result",r,"latencyMs",(System.nanoTime()-s)/1_000_000)); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @PostMapping("/add-block")
    public ResponseEntity<?> addBlock(@RequestBody Map<String,String> req) {
        try { String vid=req.get("validatorId");
            if(vid==null) return ResponseEntity.badRequest().body(Map.of("status","error","message","'validatorId' is required"));
            long s=System.nanoTime(); var r=svc.addBlock(vid,req.getOrDefault("data","block-data"));
            return ResponseEntity.ok(Map.of("status","success","result",r,"latencyMs",(System.nanoTime()-s)/1_000_000)); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @GetMapping("/chain") public ResponseEntity<?> chain() { return ResponseEntity.ok(Map.of("chain",svc.getChain())); }
    @PostMapping("/verify-chain")
    public ResponseEntity<?> verify() {
        try { return ResponseEntity.ok(Map.of("status","success","result",svc.verifyChain())); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @PostMapping("/connect-peer")
    public ResponseEntity<?> connect(@RequestBody Map<String,String> req) {
        return ResponseEntity.ok(Map.of("status","success","result",
                svc.connectPeer(req.getOrDefault("peerId","peer-1"),req.getOrDefault("address","localhost:8091"))));
    }
    @GetMapping("/peers") public ResponseEntity<?> peers() { return ResponseEntity.ok(Map.of("peers",svc.getPeers())); }
    @GetMapping("/health")
    public ResponseEntity<?> health() { return ResponseEntity.ok(Map.of("status","UP","service","blockchain-sandbox","chainLength",svc.getChain().size())); }
}
