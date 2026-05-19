package com.pqc.sandbox.nft;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class NftService {
    public record NFT(String tokenId, String name, String description, String creator, String owner,
                      String metadataHash, byte[] creatorSignature, byte[] creatorPublicKey,
                      String algorithm, Instant createdAt) {}
    public record TransferRecord(String id, String tokenId, String from, String to, Instant timestamp) {}

    private final QudoCryptoService qudo;
    private final ConcurrentHashMap<String, NFT> nfts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<TransferRecord>> history = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, QudoCryptoService.KeyMaterial> creators = new ConcurrentHashMap<>();
    private String defaultCreatorAddress;

    public NftService(QudoCryptoService qudo) { this.qudo = qudo; }

    @PostConstruct
    public void init() throws Exception {
        var keys = qudo.generateKeyPair("ML-DSA-65");
        defaultCreatorAddress = qudo.deriveAddress(keys.publicKeyPem());
        creators.put(defaultCreatorAddress, keys);
    }

    public Map<String, String> mintNFT(String name, String desc) throws Exception {
        var keys = creators.get(defaultCreatorAddress);
        String tokenId = "nft-" + UUID.randomUUID().toString().substring(0, 8);
        String canonical = name + "|" + desc + "|" + defaultCreatorAddress;
        byte[] metaHash = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes());
        byte[] sig = qudo.sign(metaHash, keys.privateKeyPem(), "ML-DSA-65");
        nfts.put(tokenId, new NFT(tokenId, name, desc, defaultCreatorAddress, defaultCreatorAddress,
                Base64.getEncoder().encodeToString(metaHash), sig, keys.publicKeyPem(), "ML-DSA-65", Instant.now()));
        history.put(tokenId, new CopyOnWriteArrayList<>());
        return Map.of("tokenId",tokenId,"name",name,"creator",defaultCreatorAddress,
                "signature",Base64.getEncoder().encodeToString(sig),
                "creatorPublicKey",Base64.getEncoder().encodeToString(keys.publicKeyPem()),
                "algorithm","ML-DSA-65");
    }

    public Map<String, String> transferNFT(String tokenId, String toAddress) throws Exception {
        NFT nft = nfts.get(tokenId); if (nft==null) throw new IllegalArgumentException("NFT not found");
        var tr = new TransferRecord("tr-"+UUID.randomUUID().toString().substring(0,8),tokenId,nft.owner,toAddress,Instant.now());
        history.get(tokenId).add(tr);
        nfts.put(tokenId, new NFT(tokenId,nft.name,nft.description,nft.creator,toAddress,
                nft.metadataHash,nft.creatorSignature,nft.creatorPublicKey,nft.algorithm,nft.createdAt));
        return Map.of("tokenId",tokenId,"from",nft.owner,"to",toAddress,"transferId",tr.id);
    }

    public Map<String, Object> verifyNFT(String tokenId) throws Exception {
        NFT nft = nfts.get(tokenId); if (nft==null) throw new IllegalArgumentException("NFT not found");
        byte[] metaHash = Base64.getDecoder().decode(nft.metadataHash);
        boolean valid = qudo.verify(metaHash, nft.creatorSignature, nft.creatorPublicKey, "ML-DSA-65");
        return Map.of("tokenId",tokenId,"valid",valid,"algorithm","ML-DSA-65","creator",nft.creator);
    }

    public NFT getNFT(String id) { return nfts.get(id); }
    public Collection<NFT> listNFTs() { return nfts.values(); }
    public List<TransferRecord> getHistory(String id) { return history.getOrDefault(id, List.of()); }
}
