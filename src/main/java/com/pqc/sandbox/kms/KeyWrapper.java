package com.pqc.sandbox.kms;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * AES-256-GCM key-encryption-key (KEK) wrapper for private keys at rest.
 * KEK is derived via SHA-256 from {@code kms.kek} property; if unset, a
 * random ephemeral KEK is generated at startup (keys won't survive restart).
 */
@Component
public class KeyWrapper {

    private static final Logger log = LoggerFactory.getLogger(KeyWrapper.class);
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;

    private final byte[] kek;
    private final SecureRandom rng = new SecureRandom();

    public KeyWrapper(@Value("${kms.kek:}") String kekMaterial) throws Exception {
        if (kekMaterial != null && !kekMaterial.isBlank()) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            this.kek = md.digest(kekMaterial.getBytes(StandardCharsets.UTF_8));
            log.info("KMS KEK loaded from kms.kek property (SHA-256 derived, 256-bit AES key)");
        } else {
            this.kek = new byte[32];
            rng.nextBytes(this.kek);
            log.warn("KMS KEK not configured. Generated random ephemeral KEK — persisted keys WILL NOT survive restart.");
        }
    }

    public Wrapped wrap(byte[] privateKeyPem) throws Exception {
        byte[] iv = new byte[IV_BYTES];
        rng.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return new Wrapped(iv, c.doFinal(privateKeyPem));
    }

    public byte[] unwrap(byte[] wrappedPrivateKey, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return c.doFinal(wrappedPrivateKey);
    }

    public record Wrapped(byte[] iv, byte[] ciphertext) {}
}
