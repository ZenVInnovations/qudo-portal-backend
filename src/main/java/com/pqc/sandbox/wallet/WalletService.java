package com.pqc.sandbox.wallet;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class WalletService {
    public record Wallet(String id, String name, String address, String algorithm, java.time.Instant createdAt) {}

    private final QudoCryptoService qudo;
    private final ConcurrentHashMap<String, Wallet> wallets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, QudoCryptoService.KeyMaterial> walletKeys = new ConcurrentHashMap<>();

    public WalletService(QudoCryptoService qudo) { this.qudo = qudo; }

    public Wallet createWallet(String name, String algorithm) throws Exception {
        String alg = algorithm != null ? algorithm : "ML-DSA-65";
        var keys = qudo.generateKeyPair(alg);
        String address = qudo.deriveAddress(keys.publicKeyPem());
        String id = "wallet-" + UUID.randomUUID().toString().substring(0, 8);
        Wallet w = new Wallet(id, name, address, alg, java.time.Instant.now());
        wallets.put(id, w);
        walletKeys.put(id, keys);
        return w;
    }

    public Map<String, Object> signTransaction(String walletId, String txData) throws Exception {
        var keys = walletKeys.get(walletId);
        if (keys == null) throw new IllegalArgumentException("Wallet not found: " + walletId);
        byte[] sig = qudo.sign(txData.getBytes(), keys.privateKeyPem(), keys.algorithm());
        return Map.of("walletId", walletId, "signature", Base64.getEncoder().encodeToString(sig),
                "publicKey", keys.publicKeyBase64(), "algorithm", keys.algorithm(), "txData", txData);
    }

    public boolean verifyTransaction(String txData, String sigB64, String pubKeyB64, String algorithm) throws Exception {
        return qudo.verify(txData.getBytes(), Base64.getDecoder().decode(sigB64), Base64.getDecoder().decode(pubKeyB64), algorithm);
    }

    public Wallet getWallet(String id) { return wallets.get(id); }
    public String getPublicKey(String id) { var k = walletKeys.get(id); return k != null ? k.publicKeyBase64() : null; }
    public Collection<Wallet> listWallets() { return wallets.values(); }
}
