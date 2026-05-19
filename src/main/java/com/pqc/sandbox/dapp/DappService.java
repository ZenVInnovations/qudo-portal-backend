package com.pqc.sandbox.dapp;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DappService {
    private final QudoCryptoService qudo;
    private final ConcurrentHashMap<String, Map<String, String>> contracts = new ConcurrentHashMap<>();
    private KeyPair ecdsaKeyPair;
    private QudoCryptoService.KeyMaterial mldsaKeys;

    public DappService(QudoCryptoService qudo) { this.qudo = qudo; }

    @PostConstruct
    public void init() throws Exception {
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        ecdsaKeyPair = ecKpg.generateKeyPair();
        mldsaKeys = qudo.generateKeyPair("ML-DSA-65");
    }

    public Map<String, String> deployContract(String code) throws Exception {
        String id = "contract-" + UUID.randomUUID().toString().substring(0, 8);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(code.getBytes());
        byte[] sig = qudo.sign(hash, mldsaKeys.privateKeyPem(), "ML-DSA-65");
        var contract = Map.of("contractId",id,"codeHash",Base64.getEncoder().encodeToString(hash),
                "signature",Base64.getEncoder().encodeToString(sig),
                "algorithm","ML-DSA-65","deployedAt",String.valueOf(System.currentTimeMillis()));
        contracts.put(id, contract);
        return contract;
    }

    public Map<String, String> dualSign(byte[] data) throws Exception {
        Signature ecSigner = Signature.getInstance("SHA256withECDSA");
        ecSigner.initSign(ecdsaKeyPair.getPrivate());
        ecSigner.update(data);
        byte[] ecSig = ecSigner.sign();
        byte[] mlSig = qudo.sign(data, mldsaKeys.privateKeyPem(), "ML-DSA-65");
        return Map.of("ecdsaSignature",Base64.getEncoder().encodeToString(ecSig),
                "mldsaSignature",Base64.getEncoder().encodeToString(mlSig),
                "ecdsaPublicKey",Base64.getEncoder().encodeToString(ecdsaKeyPair.getPublic().getEncoded()),
                "mldsaPublicKey",mldsaKeys.publicKeyBase64(),
                "ecdsaAlgorithm","SHA256withECDSA","mldsaAlgorithm","ML-DSA-65");
    }

    public Map<String, Object> dualVerify(byte[] data, byte[] ecSig, byte[] mlSig, byte[] ecPub, byte[] mlPub) throws Exception {
        KeyFactory ecKf = KeyFactory.getInstance("EC");
        PublicKey ecKey = ecKf.generatePublic(new java.security.spec.X509EncodedKeySpec(ecPub));
        Signature ecV = Signature.getInstance("SHA256withECDSA");
        ecV.initVerify(ecKey);
        ecV.update(data);
        boolean ecValid = ecV.verify(ecSig);
        boolean mlValid = qudo.verify(data, mlSig, mlPub, "ML-DSA-65");
        return Map.of("ecdsaValid",ecValid,"mldsaValid",mlValid,"bothValid",ecValid && mlValid);
    }

    public Collection<Map<String, String>> getContracts() { return contracts.values(); }
}
