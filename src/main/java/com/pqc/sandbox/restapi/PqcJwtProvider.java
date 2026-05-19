package com.pqc.sandbox.restapi;

import com.pqc.common.QudoCryptoService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PQC JWT Provider — signs and verifies JWT tokens using ML-DSA-65 via the Qudo
 * JNI provider. Asymmetric (sign with private, verify with public); public key
 * is exposed via the JWKS-like /auth/jwks endpoint for external verifiers.
 *
 * <p>JWT format: base64url(header).base64url(payload).base64url(signature).
 * Header alg: "ML-DSA-65" (JOSE PQC standardization is still in progress).</p>
 *
 * Ported from the legacy rest-api-service.
 */
@Component
public class PqcJwtProvider {

    private static final Logger log = LoggerFactory.getLogger(PqcJwtProvider.class);
    private static final long EXPIRATION_SECONDS = 3600;
    private static final String ALGORITHM = "ML-DSA-65";

    private final QudoCryptoService qudo;
    private QudoCryptoService.KeyMaterial signingKey;

    public PqcJwtProvider(QudoCryptoService qudo) { this.qudo = qudo; }

    @PostConstruct
    public void init() throws Exception {
        this.signingKey = qudo.generateKeyPair(ALGORITHM);
        log.info("PQC JWT signing key generated: ML-DSA-65 via Qudo provider");
    }

    public Map<String, Object> generateToken(String username) throws Exception {
        String header = toBase64Url("{\"alg\":\"ML-DSA-65\",\"typ\":\"JWT\"}");

        long now = Instant.now().getEpochSecond();
        long exp = now + EXPIRATION_SECONDS;
        String payloadJson = String.format(
                "{\"sub\":\"%s\",\"iat\":%d,\"exp\":%d,\"iss\":\"qudo-portal-backend\"}",
                username, now, exp);
        String payload = toBase64Url(payloadJson);

        String signingInput = header + "." + payload;
        byte[] signature = qudo.sign(
                signingInput.getBytes(StandardCharsets.UTF_8),
                signingKey.privateKeyPem(),
                ALGORITHM
        );
        String sig = toBase64Url(signature);

        String token = signingInput + "." + sig;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("token", token);
        result.put("type", "Bearer");
        result.put("algorithm", ALGORITHM);
        result.put("expiresIn", EXPIRATION_SECONDS);
        result.put("signedBy", "Qudo FIPS Provider (JNI)");
        return result;
    }

    public Map<String, Object> verifyToken(String token) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length != 3) return Map.of("valid", false, "error", "Invalid JWT format");

        String signingInput = parts[0] + "." + parts[1];
        byte[] signature = fromBase64Url(parts[2]);

        boolean valid = qudo.verify(
                signingInput.getBytes(StandardCharsets.UTF_8),
                signature,
                signingKey.publicKeyPem(),
                ALGORITHM
        );

        if (!valid) return Map.of("valid", false, "error", "Signature verification failed");

        String payloadJson = new String(fromBase64Url(parts[1]), StandardCharsets.UTF_8);
        long exp = 0;
        String sub = "";
        try {
            Matcher expMatcher = Pattern.compile("\"exp\"\\s*:\\s*(\\d+)").matcher(payloadJson);
            if (expMatcher.find()) exp = Long.parseLong(expMatcher.group(1));
            Matcher subMatcher = Pattern.compile("\"sub\"\\s*:\\s*\"([^\"]+)\"").matcher(payloadJson);
            if (subMatcher.find()) sub = subMatcher.group(1);
        } catch (Exception e) {
            return Map.of("valid", false, "error", "Failed to parse payload");
        }

        if (exp > 0 && Instant.now().getEpochSecond() > exp) {
            return Map.of("valid", false, "error", "Token expired");
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("valid", true);
        result.put("subject", sub);
        result.put("algorithm", ALGORITHM);
        result.put("verifiedBy", "Qudo FIPS Provider (JNI)");
        return result;
    }

    public Map<String, String> getPublicKeyInfo() {
        return Map.of(
                "algorithm", ALGORITHM,
                "publicKey", signingKey.publicKeyBase64(),
                "use", "sig",
                "provider", "Qudo FIPS v1.0.0"
        );
    }

    public boolean validateToken(String token) {
        try {
            Map<String, Object> result = verifyToken(token);
            return Boolean.TRUE.equals(result.get("valid"));
        } catch (Exception e) {
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return null;
            String payloadJson = new String(fromBase64Url(parts[1]), StandardCharsets.UTF_8);
            Matcher subMatcher = Pattern.compile("\"sub\"\\s*:\\s*\"([^\"]+)\"").matcher(payloadJson);
            if (subMatcher.find()) return subMatcher.group(1);
        } catch (Exception e) {
            log.debug("Failed to extract username from token: {}", e.getMessage());
        }
        return null;
    }

    private String toBase64Url(String input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }
    private String toBase64Url(byte[] input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }
    private byte[] fromBase64Url(String input) {
        return Base64.getUrlDecoder().decode(input);
    }
}
