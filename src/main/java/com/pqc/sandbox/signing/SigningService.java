package com.pqc.sandbox.signing;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.*;

/**
 * Signing service for the code/document/container-signing sandbox.
 * Supports ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) via the Qudo JNI provider.
 */
@Service
public class SigningService {

    private static final Set<String> SUPPORTED_ALGORITHMS = Set.of(
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"
    );

    private final QudoCryptoService qudo;

    public SigningService(QudoCryptoService qudo) { this.qudo = qudo; }

    public Map<String, String> sign(byte[] data, String algorithm) throws Exception {
        String signAlg = resolveAlgorithm(algorithm);
        QudoCryptoService.KeyMaterial keys = qudo.generateKeyPair(signAlg);
        byte[] signature = qudo.sign(data, keys.privateKeyPem(), signAlg);
        return Map.of(
                "signature", Base64.getEncoder().encodeToString(signature),
                "publicKey", keys.publicKeyBase64(),
                "algorithm", signAlg,
                "dataHash", Base64.getEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(data))
        );
    }

    public Map<String, Object> verify(byte[] data, byte[] signature, byte[] publicKeyPem, String algorithm) throws Exception {
        String verifyAlg = resolveAlgorithm(algorithm);
        boolean valid = qudo.verify(data, signature, publicKeyPem, verifyAlg);
        return Map.of(
                "valid", valid,
                "algorithm", verifyAlg,
                "dataSize", data.length,
                "signatureSize", signature.length
        );
    }

    public Map<String, String> signContainer(String imageDigest, String algorithm) throws Exception {
        byte[] digestBytes = imageDigest.getBytes();
        Map<String, String> result = sign(digestBytes, algorithm);
        return Map.of(
                "imageDigest", imageDigest,
                "signature", result.get("signature"),
                "publicKey", result.get("publicKey"),
                "algorithm", result.get("algorithm"),
                "type", "container-image-signature"
        );
    }

    public List<String> getSupportedAlgorithms() {
        return List.of(
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
                "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"
        );
    }

    private String resolveAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) return "ML-DSA-65";
        if (!SUPPORTED_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException(
                    "Unsupported algorithm: " + algorithm + ". Supported: " + SUPPORTED_ALGORITHMS);
        }
        return algorithm;
    }
}
