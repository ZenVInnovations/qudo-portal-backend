package com.pqc.sandbox.nft;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sandbox/nft")
public class NftSandboxController {
    private final NftService svc;
    public NftSandboxController(NftService svc) { this.svc = svc; }

    @PostMapping("/mint")
    public ResponseEntity<?> mint(@RequestBody Map<String,String> req) {
        try { long s=System.nanoTime(); var r=svc.mintNFT(req.getOrDefault("name","NFT"),req.getOrDefault("description","PQC NFT"));
            return ResponseEntity.ok(Map.of("status","success","result",r,"latencyMs",(System.nanoTime()-s)/1_000_000)); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@RequestBody Map<String,String> req) {
        try { var r=svc.transferNFT(req.get("tokenId"),req.getOrDefault("toAddress","0xnew"));
            return ResponseEntity.ok(Map.of("status","success","result",r)); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String,String> req) {
        try { var r=svc.verifyNFT(req.get("tokenId"));
            return ResponseEntity.ok(Map.of("status","success","result",r)); }
        catch(Exception e){return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage()));}
    }
    @GetMapping("/{tokenId}")
    public ResponseEntity<?> get(@PathVariable String tokenId) {
        var nft=svc.getNFT(tokenId); if(nft==null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(Map.of("tokenId",nft.tokenId(),"name",nft.name(),"owner",nft.owner(),"creator",nft.creator(),"algorithm",nft.algorithm()));
    }
    @GetMapping("/list")
    public ResponseEntity<?> list() {
        return ResponseEntity.ok(Map.of("nfts",svc.listNFTs().stream().map(n->Map.of("tokenId",n.tokenId(),"name",n.name(),"owner",n.owner())).toList()));
    }
    @GetMapping("/history/{tokenId}")
    public ResponseEntity<?> history(@PathVariable String tokenId) {
        return ResponseEntity.ok(Map.of("history",svc.getHistory(tokenId).stream().map(t->Map.of("id",t.id(),"from",t.from(),"to",t.to())).toList()));
    }
    @GetMapping("/health") public ResponseEntity<?> health() { return ResponseEntity.ok(Map.of("status","UP","service","nft-sandbox")); }
}
