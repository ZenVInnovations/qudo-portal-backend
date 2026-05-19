package com.pqc.sandbox.blockchain;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class BlockchainService {
    public record Block(int index, long timestamp, String data, String previousHash, String hash,
                        byte[] validatorSignature, String validatorAddress) {}

    private final QudoCryptoService qudo;
    private final CopyOnWriteArrayList<Block> chain = new CopyOnWriteArrayList<>();
    private final ConcurrentHashMap<String, QudoCryptoService.KeyMaterial> validators = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Map<String,String>> peers = new ConcurrentHashMap<>();

    public BlockchainService(QudoCryptoService qudo) { this.qudo = qudo; }

    @PostConstruct
    public void init() throws Exception {
        String hash = calcHash("genesis-block-0");
        chain.add(new Block(0, System.currentTimeMillis(), "Genesis Block", "0", hash, new byte[0], "system"));
    }

    public Map<String, String> registerNode(String name) throws Exception {
        String id = "node-" + UUID.randomUUID().toString().substring(0, 8);
        var keys = qudo.generateKeyPair("ML-DSA-65");
        validators.put(id, keys);
        return Map.of("nodeId",id,"name",name,"address",qudo.deriveAddress(keys.publicKeyPem()),
                "algorithm","ML-DSA-65","publicKey",keys.publicKeyBase64());
    }

    public Map<String, Object> addBlock(String validatorId, String data) throws Exception {
        var keys = validators.get(validatorId); if (keys==null) throw new IllegalArgumentException("Validator not found");
        Block prev = chain.get(chain.size()-1);
        String blockHash = calcHash(prev.hash+":"+data+":"+System.currentTimeMillis());
        byte[] sig = qudo.sign(blockHash.getBytes(), keys.privateKeyPem(), "ML-DSA-65");
        chain.add(new Block(chain.size(), System.currentTimeMillis(), data, prev.hash, blockHash, sig, validatorId));
        return Map.of("index",chain.size()-1,"hash",blockHash,"previousHash",prev.hash,
                "validator",validatorId,"algorithm","ML-DSA-65","chainLength",chain.size());
    }

    public Map<String, Object> verifyChain() throws Exception {
        int verified = 0;
        for (int i=1; i<chain.size(); i++) {
            Block b = chain.get(i);
            if (!b.previousHash.equals(chain.get(i-1).hash))
                return Map.of("valid",false,"failedAt",i,"reason","Hash mismatch at block "+i);
            var keys = validators.get(b.validatorAddress);
            if (keys == null)
                return Map.of("valid",false,"failedAt",i,"reason","Unknown validator at block "+i+": "+b.validatorAddress);
            if (!qudo.verify(b.hash.getBytes(), b.validatorSignature, keys.publicKeyPem(), "ML-DSA-65"))
                return Map.of("valid",false,"failedAt",i,"reason","Invalid signature at block "+i);
            verified++;
        }
        return Map.of("valid",true,"blocksVerified",verified,"chainLength",chain.size());
    }

    public Map<String, String> connectPeer(String peerId, String addr) {
        peers.put(peerId, Map.of("id",peerId,"address",addr,"status","CONNECTED","keyExchange","X25519MLKEM768"));
        return Map.of("peerId",peerId,"address",addr,"status","CONNECTED","keyExchange","X25519MLKEM768");
    }

    public List<Map<String, Object>> getChain() {
        return chain.stream().map(b->Map.<String,Object>of("index",b.index,"data",b.data,"hash",b.hash,
                "previousHash",b.previousHash,"validator",b.validatorAddress)).toList();
    }
    public Collection<Map<String, String>> getPeers() { return peers.values(); }

    private String calcHash(String data) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(data.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
