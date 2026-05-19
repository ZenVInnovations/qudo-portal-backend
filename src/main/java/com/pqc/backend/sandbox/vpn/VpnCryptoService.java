package com.pqc.backend.sandbox.vpn;

import com.pqc.common.QudoCryptoService;
import com.pqc.common.QudoCryptoService.KeyMaterial;
import com.pqc.common.QudoCryptoService.KemEncapsulation;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Thin wrapper around Qudo JNI for the VPN sandbox.
 *
 * ML-KEM-1024 (NIST Cat 5) for session-key establishment — VPN tunnels are
 * long-lived and often carry highly sensitive traffic, so the strongest KEM
 * is the right default. Tunnel traffic is encrypted with AES-256-GCM.
 * Per-side identity uses ML-DSA-65 (balance of security and handshake size).
 */
@Service
public class VpnCryptoService {

    public static final String KEM_ALG = "ML-KEM-1024";
    public static final String SIG_ALG = "ML-DSA-65";
    public static final int AES_KEY_BYTES = 32;
    public static final int GCM_IV_BYTES = 12;
    public static final int GCM_TAG_BITS = 128;

    private final QudoCryptoService qudo;
    private final SecureRandom random = new SecureRandom();

    public VpnCryptoService(QudoCryptoService qudo) { this.qudo = qudo; }

    public KeyMaterial generateKemKeyPair() throws Exception { return qudo.generateKeyPair(KEM_ALG); }
    public KeyMaterial generateIdentityKeyPair() throws Exception { return qudo.generateKeyPair(SIG_ALG); }

    public KemEncapsulation encapsulate(byte[] peerPubKey) throws Exception {
        return qudo.kemEncapsulate(peerPubKey, KEM_ALG);
    }

    public byte[] decapsulate(byte[] ciphertext, byte[] privKey) throws Exception {
        return qudo.kemDecapsulate(ciphertext, privKey, KEM_ALG);
    }

    public byte[] sign(byte[] data, byte[] privKey) throws Exception {
        return qudo.sign(data, privKey, SIG_ALG);
    }

    public boolean verify(byte[] data, byte[] sig, byte[] pubKey) throws Exception {
        return qudo.verify(data, sig, pubKey, SIG_ALG);
    }

    /** AES-256-GCM encrypt with a freshly-generated random 12-byte IV. Returns [iv || ciphertext]. */
    public byte[] gcmEncrypt(byte[] key, byte[] plaintext) throws Exception {
        byte[] iv = new byte[GCM_IV_BYTES];
        random.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = c.doFinal(plaintext);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    public byte[] gcmDecrypt(byte[] key, byte[] ivAndCiphertext) throws Exception {
        byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, GCM_IV_BYTES);
        byte[] ct = Arrays.copyOfRange(ivAndCiphertext, GCM_IV_BYTES, ivAndCiphertext.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return c.doFinal(ct);
    }

    /** Derive a 32-byte AES key from a raw KEM shared secret (truncate — ML-KEM-1024 secret is already 32 bytes). */
    public byte[] deriveAesKey(byte[] sharedSecret) {
        byte[] key = new byte[AES_KEY_BYTES];
        System.arraycopy(sharedSecret, 0, key, 0, Math.min(AES_KEY_BYTES, sharedSecret.length));
        return key;
    }
}
