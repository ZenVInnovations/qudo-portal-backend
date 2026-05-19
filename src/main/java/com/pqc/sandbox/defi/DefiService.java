package com.pqc.sandbox.defi;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DefiService {
    public record MultiSigWallet(String id, String name, List<QudoCryptoService.KeyMaterial> signers,
                                 List<String> addresses, int threshold) {}
    public record Proposal(String id, String walletId, String description, String data,
                            Map<String,byte[]> signatures, String status, Instant createdAt) {}

    private final QudoCryptoService qudo;
    private final ConcurrentHashMap<String, MultiSigWallet> wallets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Proposal> proposals = new ConcurrentHashMap<>();

    public DefiService(QudoCryptoService qudo) { this.qudo = qudo; }

    public Map<String, Object> createMultiSigWallet(String name, int signerCount, int threshold) throws Exception {
        String id = "msw-" + UUID.randomUUID().toString().substring(0, 8);
        List<QudoCryptoService.KeyMaterial> signers = new ArrayList<>();
        List<String> addresses = new ArrayList<>();
        for (int i = 0; i < signerCount; i++) {
            var keys = qudo.generateKeyPair("ML-DSA-65");
            signers.add(keys);
            addresses.add(qudo.deriveAddress(keys.publicKeyPem()));
        }
        wallets.put(id, new MultiSigWallet(id, name, signers, addresses, threshold));
        return Map.of("walletId",id,"name",name,"signerCount",signerCount,"threshold",threshold,
                "addresses",addresses,"algorithm","ML-DSA-65");
    }

    public Map<String, String> createProposal(String walletId, String desc, String data) {
        if (!wallets.containsKey(walletId)) throw new IllegalArgumentException("Wallet not found");
        String id = "prop-" + UUID.randomUUID().toString().substring(0, 8);
        proposals.put(id, new Proposal(id, walletId, desc, data, new ConcurrentHashMap<>(), "PENDING", Instant.now()));
        return Map.of("proposalId",id,"walletId",walletId,"status","PENDING");
    }

    public Map<String, Object> signProposal(String proposalId, int signerIndex) throws Exception {
        var prop = proposals.get(proposalId); if (prop==null) throw new IllegalArgumentException("Proposal not found");
        if (!"PENDING".equals(prop.status)) throw new IllegalArgumentException("Proposal is "+prop.status+", cannot sign");
        var wallet = wallets.get(prop.walletId);
        if (signerIndex >= wallet.signers.size() || signerIndex < 0)
            throw new IllegalArgumentException("Invalid signer index: "+signerIndex);
        String signerAddr = wallet.addresses.get(signerIndex);
        if (prop.signatures.containsKey(signerAddr))
            throw new IllegalArgumentException("Signer "+signerAddr+" already signed this proposal");
        byte[] sig = qudo.sign(prop.data.getBytes(), wallet.signers.get(signerIndex).privateKeyPem(), "ML-DSA-65");
        prop.signatures.put(signerAddr, sig);
        return Map.of("proposalId",proposalId,"signerAddress",signerAddr,
                "totalSignatures",prop.signatures.size(),"requiredSignatures",wallet.threshold);
    }

    public Map<String, Object> executeProposal(String proposalId) throws Exception {
        var prop = proposals.get(proposalId); if (prop==null) throw new IllegalArgumentException("Proposal not found");
        var wallet = wallets.get(prop.walletId);
        if (prop.signatures.size() < wallet.threshold)
            return Map.of("status","REJECTED","reason","Not enough sigs: "+prop.signatures.size()+"/"+wallet.threshold);
        int verified = 0;
        for (var e : prop.signatures.entrySet()) {
            int idx = wallet.addresses.indexOf(e.getKey());
            if (idx >= 0 && qudo.verify(prop.data.getBytes(), e.getValue(),
                    wallet.signers.get(idx).publicKeyPem(), "ML-DSA-65")) verified++;
        }
        String status = verified >= wallet.threshold ? "APPROVED" : "REJECTED";
        proposals.put(proposalId, new Proposal(prop.id,prop.walletId,prop.description,prop.data,
                prop.signatures,status,prop.createdAt));
        return Map.of("proposalId",proposalId,"status",status,"verifiedSignatures",verified,"threshold",wallet.threshold);
    }

    public Collection<Map<String, Object>> listWallets() {
        return wallets.values().stream().map(w->Map.<String,Object>of("id",w.id,"name",w.name,
                "threshold",w.threshold,"signers",w.addresses.size(),"addresses",w.addresses)).toList();
    }
    public Collection<Map<String, Object>> listProposals() {
        return proposals.values().stream().map(p->{
            var wallet = wallets.get(p.walletId);
            int threshold = wallet != null ? wallet.threshold : 0;
            return Map.<String,Object>of("id",p.id,"walletId",p.walletId,"description",p.description,"status",p.status,
                "signaturesCollected",p.signatures.size(),"threshold",threshold);
        }).toList();
    }
}
