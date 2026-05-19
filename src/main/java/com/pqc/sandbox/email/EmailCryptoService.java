package com.pqc.sandbox.email;

import com.pqc.common.QudoCryptoService;
import com.pqc.common.QudoCryptoService.KemEncapsulation;
import com.pqc.common.QudoCryptoService.KeyMaterial;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PQC email encryption sandbox. ML-KEM (FIPS 203) for key establishment +
 * AES-256-GCM for message encryption + ML-DSA (FIPS 204) for sender
 * authentication. Implements the sign-then-encrypt S/MIME pattern via the
 * Qudo JNI provider.
 */
@Service
public class EmailCryptoService {

    private static final Set<String> VALID_KEM_ALGORITHMS = Set.of("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024");
    private static final Set<String> VALID_SIG_ALGORITHMS = Set.of("ML-DSA-44", "ML-DSA-65", "ML-DSA-87");
    private static final String DEFAULT_KEM_ALGORITHM = "ML-KEM-768";
    private static final String DEFAULT_SIG_ALGORITHM = "ML-DSA-65";
    private static final int MAX_MESSAGE_SIZE = 1_048_576;

    private final QudoCryptoService qudo;
    private final ConcurrentHashMap<String, KeyMaterial> kemKeys = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, KeyMaterial> sigKeys = new ConcurrentHashMap<>();

    public EmailCryptoService(QudoCryptoService qudo) { this.qudo = qudo; }

    public Map<String, String> registerRecipientKeys(String recipientId, String algorithm) throws Exception {
        validateId(recipientId, "recipientId");
        String algo = resolveKemAlgorithm(algorithm);
        KeyMaterial keys = qudo.generateKeyPair(algo);
        kemKeys.put(recipientId, keys);
        return Map.of("recipientId", recipientId, "algorithm", algo,
                "publicKey", keys.publicKeyBase64(), "status", "registered");
    }

    public Map<String, String> registerSenderKeys(String senderId, String algorithm) throws Exception {
        validateId(senderId, "senderId");
        String algo = resolveSigAlgorithm(algorithm);
        KeyMaterial keys = qudo.generateKeyPair(algo);
        sigKeys.put(senderId, keys);
        return Map.of("senderId", senderId, "algorithm", algo,
                "publicKey", keys.publicKeyBase64(), "status", "registered");
    }

    public Map<String, String> getRecipientPublicKey(String recipientId) {
        validateId(recipientId, "recipientId");
        KeyMaterial keys = kemKeys.get(recipientId);
        if (keys == null) throw new IllegalArgumentException("No KEM key registered for recipient: " + recipientId);
        return Map.of("recipientId", recipientId, "algorithm", keys.algorithm(),
                "publicKey", keys.publicKeyBase64());
    }

    public Map<String, Object> listKeys() {
        List<Map<String, String>> recipients = new ArrayList<>();
        kemKeys.forEach((id, k) -> recipients.add(Map.of("id", id, "algorithm", k.algorithm(), "type", "KEM")));
        List<Map<String, String>> senders = new ArrayList<>();
        sigKeys.forEach((id, k) -> senders.add(Map.of("id", id, "algorithm", k.algorithm(), "type", "DSA")));
        return Map.of("recipients", recipients, "senders", senders);
    }

    public Map<String, String> encryptMessage(String plaintext, String recipientId, String algorithm) throws Exception {
        validateMessage(plaintext);
        validateId(recipientId, "recipientId");

        String kemAlgo = resolveKemAlgorithm(algorithm);
        if (!kemKeys.containsKey(recipientId)) registerRecipientKeys(recipientId, kemAlgo);

        KeyMaterial recipientKey = kemKeys.get(recipientId);
        KemEncapsulation encap = qudo.kemEncapsulate(recipientKey.publicKeyPem(), recipientKey.algorithm());
        byte[] aesKey = deriveAesKey(encap.sharedSecret());

        byte[] plaintextBytes = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        Arrays.fill(aesKey, (byte) 0);

        return Map.of(
                "ciphertext", Base64.getEncoder().encodeToString(ciphertext),
                "encapsulatedKey", Base64.getEncoder().encodeToString(encap.ciphertext()),
                "iv", Base64.getEncoder().encodeToString(iv),
                "recipientId", recipientId,
                "algorithm", recipientKey.algorithm() + " + AES-256-GCM"
        );
    }

    public Map<String, String> decryptMessage(String ciphertextB64, String encapsulatedKeyB64,
                                              String ivB64, String recipientId) throws Exception {
        validateId(recipientId, "recipientId");
        requireNonBlank(ciphertextB64, "ciphertext");
        requireNonBlank(encapsulatedKeyB64, "encapsulatedKey");
        requireNonBlank(ivB64, "iv");

        KeyMaterial recipientKey = kemKeys.get(recipientId);
        if (recipientKey == null) {
            throw new IllegalArgumentException("No KEM key registered for recipient: " + recipientId
                    + ". Register keys first via POST /register-keys");
        }

        byte[] kemCiphertext = Base64.getDecoder().decode(encapsulatedKeyB64);
        byte[] sharedSecret = qudo.kemDecapsulate(kemCiphertext, recipientKey.privateKeyPem(), recipientKey.algorithm());
        byte[] aesKey = deriveAesKey(sharedSecret);
        Arrays.fill(sharedSecret, (byte) 0);

        byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
        byte[] iv = Base64.getDecoder().decode(ivB64);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
        byte[] plaintext = cipher.doFinal(ciphertext);
        Arrays.fill(aesKey, (byte) 0);

        return Map.of("plaintext", new String(plaintext, java.nio.charset.StandardCharsets.UTF_8),
                "algorithm", recipientKey.algorithm() + " + AES-256-GCM");
    }

    public Map<String, String> signMessage(String message, String senderId, String algorithm) throws Exception {
        validateMessage(message);
        validateId(senderId, "senderId");

        String sigAlgo = resolveSigAlgorithm(algorithm);
        if (!sigKeys.containsKey(senderId)) registerSenderKeys(senderId, sigAlgo);

        KeyMaterial senderKey = sigKeys.get(senderId);
        byte[] signature = qudo.sign(message.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                senderKey.privateKeyPem(), senderKey.algorithm());

        return Map.of("message", message,
                "signature", Base64.getEncoder().encodeToString(signature),
                "publicKey", senderKey.publicKeyBase64(),
                "senderId", senderId,
                "algorithm", senderKey.algorithm());
    }

    public Map<String, Object> verifyMessage(String message, String signatureB64,
                                             String publicKeyB64, String algorithm) throws Exception {
        validateMessage(message);
        requireNonBlank(signatureB64, "signature");
        requireNonBlank(publicKeyB64, "publicKey");

        String sigAlgo = resolveSigAlgorithm(algorithm);
        boolean valid = qudo.verify(
                message.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                Base64.getDecoder().decode(signatureB64),
                Base64.getDecoder().decode(publicKeyB64),
                sigAlgo);
        return Map.of("valid", valid, "algorithm", sigAlgo);
    }

    public Map<String, Object> sendSecureEmail(String message, String senderId, String recipientId,
                                               String kemAlgorithm, String sigAlgorithm) throws Exception {
        validateMessage(message);
        validateId(senderId, "senderId");
        validateId(recipientId, "recipientId");

        Map<String, String> signed = signMessage(message, senderId, sigAlgorithm);
        String envelope = buildSignedEnvelope(message, signed.get("signature"),
                signed.get("publicKey"), signed.get("algorithm"));
        Map<String, String> encrypted = encryptMessage(envelope, recipientId, kemAlgorithm);

        return Map.of(
                "ciphertext", encrypted.get("ciphertext"),
                "encapsulatedKey", encrypted.get("encapsulatedKey"),
                "iv", encrypted.get("iv"),
                "senderPublicKey", signed.get("publicKey"),
                "recipientId", recipientId,
                "senderId", senderId,
                "encryptionAlgorithm", encrypted.get("algorithm"),
                "signatureAlgorithm", signed.get("algorithm"));
    }

    public Map<String, Object> receiveSecureEmail(String ciphertextB64, String encapsulatedKeyB64,
                                                  String ivB64, String recipientId) throws Exception {
        Map<String, String> decrypted = decryptMessage(ciphertextB64, encapsulatedKeyB64, ivB64, recipientId);
        Map<String, String> envelope = parseSignedEnvelope(decrypted.get("plaintext"));
        Map<String, Object> verification = verifyMessage(
                envelope.get("message"), envelope.get("signature"),
                envelope.get("senderPublicKey"), envelope.get("signatureAlgorithm"));

        boolean valid = (boolean) verification.get("valid");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("plaintext", envelope.get("message"));
        result.put("signatureValid", valid);
        result.put("signatureAlgorithm", envelope.get("signatureAlgorithm"));
        result.put("encryptionAlgorithm", decrypted.get("algorithm"));
        result.put("senderPublicKey", envelope.get("senderPublicKey"));
        return result;
    }

    private byte[] deriveAesKey(byte[] sharedSecret) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("pqc-email-aes-key".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return md.digest(sharedSecret);
    }

    private String buildSignedEnvelope(String message, String signature,
                                       String senderPublicKey, String signatureAlgorithm) {
        return "{\"message\":" + jsonEscape(message)
                + ",\"signature\":\"" + signature + "\""
                + ",\"senderPublicKey\":\"" + senderPublicKey + "\""
                + ",\"signatureAlgorithm\":\"" + signatureAlgorithm + "\"}";
    }

    private Map<String, String> parseSignedEnvelope(String json) {
        try {
            Map<String, String> result = new LinkedHashMap<>();
            result.put("message", extractJsonString(json, "message"));
            result.put("signature", extractJsonString(json, "signature"));
            result.put("senderPublicKey", extractJsonString(json, "senderPublicKey"));
            result.put("signatureAlgorithm", extractJsonString(json, "signatureAlgorithm"));
            return result;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid signed envelope format. Expected structured JSON from /send-secure.", e);
        }
    }

    private String extractJsonString(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start < 0) throw new IllegalArgumentException("Missing field: " + key);
        start += search.length();
        int end = json.indexOf("\"", start);
        while (end > 0 && json.charAt(end - 1) == '\\') end = json.indexOf("\"", end + 1);
        if (end < 0) throw new IllegalArgumentException("Malformed field: " + key);
        return json.substring(start, end).replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private String jsonEscape(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private String resolveKemAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) return DEFAULT_KEM_ALGORITHM;
        if (!VALID_KEM_ALGORITHMS.contains(algorithm))
            throw new IllegalArgumentException("Unsupported KEM algorithm: " + algorithm + ". Supported: " + VALID_KEM_ALGORITHMS);
        return algorithm;
    }

    private String resolveSigAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) return DEFAULT_SIG_ALGORITHM;
        if (!VALID_SIG_ALGORITHMS.contains(algorithm))
            throw new IllegalArgumentException("Unsupported signature algorithm: " + algorithm + ". Supported: " + VALID_SIG_ALGORITHMS);
        return algorithm;
    }

    private void validateMessage(String message) {
        if (message == null || message.isEmpty()) throw new IllegalArgumentException("Message must not be null or empty");
        if (message.length() > MAX_MESSAGE_SIZE)
            throw new IllegalArgumentException("Message exceeds maximum size of " + MAX_MESSAGE_SIZE + " bytes");
    }

    private void validateId(String id, String fieldName) {
        if (id == null || id.isBlank()) throw new IllegalArgumentException(fieldName + " must not be null or blank");
        if (id.length() > 128) throw new IllegalArgumentException(fieldName + " must not exceed 128 characters");
    }

    private void requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(fieldName + " must not be null or blank");
    }
}
