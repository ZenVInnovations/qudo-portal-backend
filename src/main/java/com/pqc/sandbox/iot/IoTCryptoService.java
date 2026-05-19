package com.pqc.sandbox.iot;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class IoTCryptoService {
    private final QudoCryptoService qudo;
    public IoTCryptoService(QudoCryptoService qudo) { this.qudo = qudo; }

    public QudoCryptoService.KeyMaterial generateDeviceKeyPair() throws Exception { return qudo.generateKeyPair("ML-DSA-44"); }
    public QudoCryptoService.KeyMaterial generateVendorKeyPair() throws Exception { return qudo.generateKeyPair("ML-DSA-87"); }

    public Map<String, String> signTelemetry(byte[] data, byte[] privateKey) throws Exception {
        byte[] sig = qudo.sign(data, privateKey, "ML-DSA-44");
        return Map.of("signature", Base64.getEncoder().encodeToString(sig), "algorithm", "ML-DSA-44");
    }
    public boolean verifyTelemetry(byte[] data, byte[] sig, byte[] publicKey) throws Exception { return qudo.verify(data, sig, publicKey, "ML-DSA-44"); }

    public Map<String, String> signFirmware(byte[] hash, byte[] privateKey) throws Exception {
        byte[] sig = qudo.sign(hash, privateKey, "ML-DSA-87");
        return Map.of("signature", Base64.getEncoder().encodeToString(sig), "algorithm", "ML-DSA-87");
    }
    public boolean verifyFirmware(byte[] hash, byte[] sig, byte[] publicKey) throws Exception { return qudo.verify(hash, sig, publicKey, "ML-DSA-87"); }
}
