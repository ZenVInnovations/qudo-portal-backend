package com.pqc.sandbox.kms;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Cloud KMS sandbox — keypair lifecycle (create/sign/verify/rotate/destroy)
 * with KEK-wrapped private keys at rest and an audit log. In-memory storage
 * (ConcurrentHashMap) for the sandbox; the legacy service used JPA + H2 for
 * the same shape with a different backing store.
 *
 * Replace the in-memory stores with JPA repos when the BE adopts a DB.
 */
@Service
public class KmsService {

    private static final List<String> SUPPORTED_SIGN_ALGORITHMS = List.of("ML-DSA-44", "ML-DSA-65", "ML-DSA-87");

    private final QudoCryptoService qudo;
    private final KeyWrapper wrapper;

    private static final class KmsKey {
        final String keyId;
        final String alias;
        final String algorithm;
        final String usage;
        volatile String status;
        final Instant createdAt;
        volatile Instant rotatedAt;
        final byte[] publicKeyPem;
        final byte[] wrappedPrivateKey;
        final byte[] wrapIv;

        KmsKey(String keyId, String alias, String algorithm, String usage, String status,
               Instant createdAt, byte[] publicKeyPem, byte[] wrappedPrivateKey, byte[] wrapIv) {
            this.keyId = keyId;
            this.alias = alias;
            this.algorithm = algorithm;
            this.usage = usage;
            this.status = status;
            this.createdAt = createdAt;
            this.publicKeyPem = publicKeyPem;
            this.wrappedPrivateKey = wrappedPrivateKey;
            this.wrapIv = wrapIv;
        }
    }

    private record AuditRecord(String keyId, String operation, String actor, Instant timestamp, String details) {}

    private final ConcurrentHashMap<String, KmsKey> keys = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<AuditRecord> auditLog = new CopyOnWriteArrayList<>();

    public KmsService(QudoCryptoService qudo, KeyWrapper wrapper) {
        this.qudo = qudo;
        this.wrapper = wrapper;
    }

    public Map<String, String> createKey(String alias, String algorithm, String usage) throws Exception {
        String alg = algorithm != null ? algorithm : "ML-DSA-65";
        if (!SUPPORTED_SIGN_ALGORITHMS.contains(alg)) {
            throw new IllegalArgumentException("Unsupported algorithm: " + alg + ". Supported: " + SUPPORTED_SIGN_ALGORITHMS);
        }
        QudoCryptoService.KeyMaterial keyMat = qudo.generateKeyPair(alg);
        KeyWrapper.Wrapped wrapped = wrapper.wrap(keyMat.privateKeyPem());

        String keyId = "key-" + UUID.randomUUID().toString().substring(0, 8);
        KmsKey k = new KmsKey(keyId, alias, alg, usage != null ? usage : "SIGN", "ACTIVE",
                Instant.now(), keyMat.publicKeyPem(), wrapped.ciphertext(), wrapped.iv());
        keys.put(keyId, k);
        audit(keyId, "CREATE", "system", "Created " + alg + " key, alias: " + alias);

        return Map.of("keyId", keyId, "alias", alias, "algorithm", alg,
                "usage", k.usage, "status", "ACTIVE");
    }

    public Map<String, String> getKeyMetadata(String keyId) {
        KmsKey k = keys.get(keyId);
        if (k == null) throw new IllegalArgumentException("Key not found: " + keyId);
        Map<String, String> out = new java.util.LinkedHashMap<>();
        out.put("keyId", k.keyId);
        out.put("alias", k.alias);
        out.put("algorithm", k.algorithm);
        out.put("usage", k.usage);
        out.put("status", k.status);
        out.put("createdAt", k.createdAt.toString());
        if (k.rotatedAt != null) out.put("rotatedAt", k.rotatedAt.toString());
        return out;
    }

    public Map<String, String> sign(String keyId, byte[] data) throws Exception {
        KmsKey k = keys.get(keyId);
        if (k == null) throw new IllegalArgumentException("Key not found");
        if (!"ACTIVE".equals(k.status)) throw new IllegalStateException("Key is " + k.status);

        byte[] privKey = wrapper.unwrap(k.wrappedPrivateKey, k.wrapIv);
        try {
            byte[] sig = qudo.sign(data, privKey, k.algorithm);
            audit(keyId, "SIGN", "system", "Signed " + data.length + " bytes with " + k.algorithm);
            return Map.of("signature", Base64.getEncoder().encodeToString(sig),
                    "keyId", keyId, "algorithm", k.algorithm);
        } finally {
            Arrays.fill(privKey, (byte) 0);
        }
    }

    public Map<String, Object> verify(String keyId, byte[] data, byte[] sig) throws Exception {
        KmsKey k = keys.get(keyId);
        if (k == null) throw new IllegalArgumentException("Key not found");
        if ("DESTROYED".equals(k.status)) throw new IllegalStateException("Key is DESTROYED");
        boolean valid = qudo.verify(data, sig, k.publicKeyPem, k.algorithm);
        audit(keyId, "VERIFY", "system", "Verified signature, result: " + valid);
        return Map.of("valid", valid, "keyId", keyId, "algorithm", k.algorithm);
    }

    public Map<String, String> rotateKey(String keyId) throws Exception {
        KmsKey old = keys.get(keyId);
        if (old == null) throw new IllegalArgumentException("Key not found");
        old.status = "ROTATED";
        old.rotatedAt = Instant.now();
        audit(keyId, "ROTATE", "system", "Key rotated, old key marked ROTATED");

        Map<String, String> newKey = createKey(old.alias + "-rotated", old.algorithm, old.usage);
        audit(newKey.get("keyId"), "ROTATE_NEW", "system", "New key created from rotation of " + keyId);
        return newKey;
    }

    public void destroyKey(String keyId) {
        KmsKey k = keys.get(keyId);
        if (k == null) throw new IllegalArgumentException("Key not found");
        k.status = "DESTROYED";
        audit(keyId, "DESTROY", "system", "Key destroyed");
    }

    public List<Map<String, String>> listKeys() {
        return keys.values().stream()
                .map(k -> Map.of("keyId", k.keyId, "alias", k.alias,
                        "algorithm", k.algorithm, "usage", k.usage,
                        "status", k.status, "createdAt", k.createdAt.toString()))
                .toList();
    }

    public List<Map<String, String>> getAuditLog(String keyId) {
        return auditLog.stream()
                .filter(a -> keyId == null || keyId.equals(a.keyId))
                .sorted((a, b) -> b.timestamp.compareTo(a.timestamp))
                .map(a -> Map.of(
                        "keyId", a.keyId == null ? "" : a.keyId,
                        "operation", a.operation,
                        "user", a.actor,
                        "timestamp", a.timestamp.toString(),
                        "details", a.details == null ? "" : a.details))
                .toList();
    }

    private void audit(String keyId, String operation, String actor, String details) {
        auditLog.add(new AuditRecord(keyId, operation, actor, Instant.now(), details));
    }
}
