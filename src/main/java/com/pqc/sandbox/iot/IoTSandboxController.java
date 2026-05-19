package com.pqc.sandbox.iot;

import com.pqc.common.QudoCryptoService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.annotation.PostConstruct;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/v1/sandbox/iot")
public class IoTSandboxController {
    private final IoTCryptoService cryptoService;
    private record DeviceInfo(String id, String name, QudoCryptoService.KeyMaterial keys, String status, long registeredAt) {}
    private final ConcurrentHashMap<String, DeviceInfo> devices = new ConcurrentHashMap<>();
    private QudoCryptoService.KeyMaterial vendorKeys;

    public IoTSandboxController(IoTCryptoService cryptoService) { this.cryptoService = cryptoService; }

    @PostConstruct
    public void init() throws Exception { this.vendorKeys = cryptoService.generateVendorKeyPair(); }

    @PostMapping("/register-device")
    public ResponseEntity<?> registerDevice(@RequestBody Map<String, String> req) {
        try {
            String name = req.getOrDefault("name", "IoT-Device");
            String id = "dev-" + UUID.randomUUID().toString().substring(0, 8);
            long start = System.nanoTime();
            var keys = cryptoService.generateDeviceKeyPair();
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            devices.put(id, new DeviceInfo(id, name, keys, "ACTIVE", System.currentTimeMillis()));
            return ResponseEntity.ok(Map.of("status","success","deviceId",id,"name",name,
                    "algorithm","ML-DSA-44","keyGenLatencyMs",elapsed,"publicKey", keys.publicKeyBase64()));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody Map<String, String> req) {
        try {
            var dev = devices.get(req.get("deviceId"));
            if (dev == null) return ResponseEntity.badRequest().body(Map.of("status","error","message","Device not found"));
            byte[] challenge = UUID.randomUUID().toString().getBytes();
            long start = System.nanoTime();
            var sig = cryptoService.signTelemetry(challenge, dev.keys.privateKeyPem());
            boolean valid = cryptoService.verifyTelemetry(challenge, Base64.getDecoder().decode(sig.get("signature")), dev.keys.publicKeyPem());
            return ResponseEntity.ok(Map.of("status","success","deviceId",dev.id,"authenticated",valid,
                    "algorithm","ML-DSA-44","latencyMs",(System.nanoTime()-start)/1_000_000));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }

    @PostMapping("/send-telemetry")
    public ResponseEntity<?> sendTelemetry(@RequestBody Map<String, String> req) {
        try {
            var dev = devices.get(req.get("deviceId"));
            if (dev == null) return ResponseEntity.badRequest().body(Map.of("status","error","message","Device not found"));
            String data = req.getOrDefault("data", "{\"temperature\":22.5}");
            long start = System.nanoTime();
            var sig = cryptoService.signTelemetry(data.getBytes(), dev.keys.privateKeyPem());
            boolean verified = cryptoService.verifyTelemetry(data.getBytes(), Base64.getDecoder().decode(sig.get("signature")), dev.keys.publicKeyPem());
            return ResponseEntity.ok(Map.of("status","success","deviceId",dev.id,"telemetry",data,"verified",verified,
                    "algorithm","ML-DSA-44","latencyMs",(System.nanoTime()-start)/1_000_000));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }

    @PostMapping("/firmware-update")
    public ResponseEntity<?> firmwareUpdate(@RequestBody Map<String, String> req) {
        try {
            var dev = devices.get(req.get("deviceId"));
            if (dev == null) return ResponseEntity.badRequest().body(Map.of("status","error","message","Device not found"));
            byte[] fwHash = MessageDigest.getInstance("SHA-256").digest(req.getOrDefault("firmwareData","FW").getBytes());
            long start = System.nanoTime();
            var sig = cryptoService.signFirmware(fwHash, vendorKeys.privateKeyPem());
            boolean verified = cryptoService.verifyFirmware(fwHash, Base64.getDecoder().decode(sig.get("signature")), vendorKeys.publicKeyPem());
            return ResponseEntity.ok(Map.of("status","success","deviceId",dev.id,"verified",verified,
                    "updateStatus",verified?"FIRMWARE_ACCEPTED":"FIRMWARE_REJECTED",
                    "signatureAlgorithm","ML-DSA-87","latencyMs",(System.nanoTime()-start)/1_000_000));
        } catch (Exception e) { return ResponseEntity.badRequest().body(Map.of("status","error","message",e.getMessage())); }
    }

    @GetMapping("/devices")
    public ResponseEntity<?> listDevices() {
        var list = devices.values().stream().map(d -> Map.of("deviceId",d.id,"name",d.name,"status",d.status,"algorithm","ML-DSA-44")).toList();
        return ResponseEntity.ok(Map.of("devices",list,"count",list.size()));
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() { return ResponseEntity.ok(Map.of("status","UP","service","iot-sandbox","registeredDevices",devices.size())); }
}
