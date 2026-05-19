package com.pqc.sandbox.dapp;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sandbox/dapp")
public class DappSandboxController {
    private final DappService dappService;
    public DappSandboxController(DappService dappService) { this.dappService = dappService; }

    @PostMapping("/deploy-contract")
    public ResponseEntity<?> deploy(@RequestBody Map<String, String> req) {
        try {
            long start = System.nanoTime();
            var result = dappService.deployContract(req.getOrDefault("code", "contract{}"));
            return ResponseEntity.ok(Map.of("status","success","contract",result,"latencyMs",(System.nanoTime()-start)/1_000_000));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }

    @PostMapping("/dual-sign")
    public ResponseEntity<?> dualSign(@RequestBody Map<String, String> req) {
        try {
            String dataStr = req.get("data");
            if (dataStr == null || dataStr.isEmpty())
                return ResponseEntity.badRequest().body(Map.of("status","error","message","'data' (base64) is required"));
            byte[] data = Base64.getDecoder().decode(dataStr);
            long start = System.nanoTime();
            var result = dappService.dualSign(data);
            return ResponseEntity.ok(Map.of("status","success","result",result,"latencyMs",(System.nanoTime()-start)/1_000_000));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }

    @PostMapping("/dual-verify")
    public ResponseEntity<?> dualVerify(@RequestBody Map<String, String> req) {
        try {
            String[] required = {"data","ecdsaSignature","mldsaSignature","ecdsaPublicKey","mldsaPublicKey"};
            for (String f : required) {
                if (req.get(f) == null) return ResponseEntity.badRequest().body(Map.of("status","error","message","'" + f + "' (base64) is required"));
            }
            byte[] data = Base64.getDecoder().decode(req.get("data"));
            byte[] ecSig = Base64.getDecoder().decode(req.get("ecdsaSignature"));
            byte[] mlSig = Base64.getDecoder().decode(req.get("mldsaSignature"));
            byte[] ecPub = Base64.getDecoder().decode(req.get("ecdsaPublicKey"));
            byte[] mlPub = Base64.getDecoder().decode(req.get("mldsaPublicKey"));
            var result = dappService.dualVerify(data, ecSig, mlSig, ecPub, mlPub);
            return ResponseEntity.ok(Map.of("status","success","result",result));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }

    @GetMapping("/contracts") public ResponseEntity<?> contracts() { return ResponseEntity.ok(Map.of("contracts", dappService.getContracts())); }
    @GetMapping("/health") public ResponseEntity<?> health() { return ResponseEntity.ok(Map.of("status","UP","service","dapp-sandbox","algorithms","ECDSA+ML-DSA-65")); }
}
