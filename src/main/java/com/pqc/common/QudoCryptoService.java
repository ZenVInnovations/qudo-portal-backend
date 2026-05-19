package com.pqc.common;

import com.qudo.crypto.QudoKeyPair;
import com.qudo.crypto.QudoKemResult;
import com.qudo.crypto.QudoCrypto;
import com.qudo.crypto.exception.QudoCryptoException;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * PQC Crypto Service — fully backed by the QUDO JNI provider.
 *
 * <p>All operations (key generation, signing, verification, certificate
 * creation, CSR, hashing) use direct JNI calls to OpenSSL via the
 * QUDO FIPS provider. No process spawning. No temp files.</p>
 */
@Service
public class QudoCryptoService {

    private QudoCrypto provider;

    public QudoCryptoService() {}

    @PostConstruct
    public void init() throws Exception {
        this.provider = QudoCrypto.create();
    }

    @PreDestroy
    public void shutdown() {
        if (provider != null) provider.close();
    }

    // ==================== Key Generation ====================

    public KeyMaterial generateKeyPair(String algorithm) throws Exception {
        try {
            String params = null;
            String algo = algorithm;
            if (algorithm.startsWith("EC:")) {
                algo = "EC";
                params = algorithm.split(":")[1];
            }
            QudoKeyPair keys = provider.generateKeyPair(algo, params);
            return new KeyMaterial(algorithm, keys.getPrivateKeyPem(), keys.getPublicKeyPem());
        } catch (QudoCryptoException e) {
            throw new RuntimeException("Key generation failed for " + algorithm + ": " + e.getMessage(), e);
        }
    }

    // ==================== Signing ====================

    public byte[] sign(byte[] data, byte[] privateKeyPem, String algorithm) throws Exception {
        try {
            return provider.sign(data, privateKeyPem, algorithm != null ? algorithm : "ML-DSA-65");
        } catch (QudoCryptoException e) {
            throw new RuntimeException("Signing failed: " + e.getMessage(), e);
        }
    }

    public boolean verify(byte[] data, byte[] signature, byte[] publicKeyPem, String algorithm) throws Exception {
        try {
            return provider.verify(data, signature, publicKeyPem, algorithm != null ? algorithm : "ML-DSA-65");
        } catch (QudoCryptoException e) {
            throw new RuntimeException("Verification failed: " + e.getMessage(), e);
        }
    }

    // ==================== Certificate Operations ====================

    public byte[] createSelfSignedCert(byte[] privateKeyPem, String subject, String algorithm, int days) throws Exception {
        try {
            return provider.createSelfSignedCert(privateKeyPem, subject, days);
        } catch (QudoCryptoException e) {
            throw new RuntimeException("Certificate creation failed: " + e.getMessage(), e);
        }
    }

    public byte[] createSelfSignedCert(byte[] privateKeyPem, String subject, int days) throws Exception {
        return createSelfSignedCert(privateKeyPem, subject, null, days);
    }

    public byte[] createCSR(byte[] privateKeyPem, String subject) throws Exception {
        try {
            return provider.createCSR(privateKeyPem, subject);
        } catch (QudoCryptoException e) {
            throw new RuntimeException("CSR creation failed: " + e.getMessage(), e);
        }
    }

    public byte[] signCSR(byte[] csrPem, byte[] caKeyPem, byte[] caCertPem, int days) throws Exception {
        try {
            return provider.signCSR(csrPem, caKeyPem, caCertPem, days);
        } catch (QudoCryptoException e) {
            throw new RuntimeException("CSR signing failed: " + e.getMessage(), e);
        }
    }

    // ==================== Key Encapsulation (KEM) ====================

    public KemEncapsulation kemEncapsulate(byte[] publicKeyPem, String algorithm) throws Exception {
        try {
            QudoKemResult result = provider.kemEncapsulate(publicKeyPem, algorithm != null ? algorithm : "ML-KEM-768");
            byte[] ciphertext = result.getCiphertext();
            byte[] sharedSecret = result.getSharedSecret();
            result.destroy();
            return new KemEncapsulation(ciphertext, sharedSecret);
        } catch (QudoCryptoException e) {
            throw new RuntimeException("KEM encapsulation failed: " + e.getMessage(), e);
        }
    }

    public byte[] kemDecapsulate(byte[] ciphertext, byte[] privateKeyPem, String algorithm) throws Exception {
        try {
            return provider.kemDecapsulate(ciphertext, privateKeyPem, algorithm != null ? algorithm : "ML-KEM-768");
        } catch (QudoCryptoException e) {
            throw new RuntimeException("KEM decapsulation failed: " + e.getMessage(), e);
        }
    }

    // ==================== Hashing ====================

    public byte[] sha256(byte[] data) throws Exception {
        try {
            return provider.sha256(data);
        } catch (QudoCryptoException e) {
            throw new RuntimeException("SHA-256 failed: " + e.getMessage(), e);
        }
    }

    // ==================== Utility ====================

    public String deriveAddress(byte[] publicKey) throws Exception {
        byte[] hash = sha256(publicKey);
        StringBuilder sb = new StringBuilder("0x");
        for (int i = 0; i < 20; i++) sb.append(String.format("%02x", hash[i]));
        return sb.toString();
    }

    public List<String> getSupportedAlgorithms() {
        return List.of(
                "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
                "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"
        );
    }

    public QudoCrypto getProvider() {
        return provider;
    }

    // ==================== Data Classes ====================

    public record KemEncapsulation(byte[] ciphertext, byte[] sharedSecret) {
        public String ciphertextBase64() { return Base64.getEncoder().encodeToString(ciphertext); }
        public String sharedSecretBase64() { return Base64.getEncoder().encodeToString(sharedSecret); }
    }

    public record KeyMaterial(String algorithm, byte[] privateKeyPem, byte[] publicKeyPem) implements java.io.Serializable {
        public String privateKeyBase64() { return Base64.getEncoder().encodeToString(privateKeyPem); }
        public String publicKeyBase64() { return Base64.getEncoder().encodeToString(publicKeyPem); }
        public String privateKeyString() { return new String(privateKeyPem); }
        public String publicKeyString() { return new String(publicKeyPem); }
    }
}
