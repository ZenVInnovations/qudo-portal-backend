package com.pqc.sandbox.exchange;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class ExchangeService {
    private final QudoCryptoService qudo;
    private record CustodyWallet(String id, String name, String address, QudoCryptoService.KeyMaterial keys) {}
    private record Transaction(String id, String walletId, String type, String amount, String asset, String signature, long ts) {}
    private final ConcurrentHashMap<String, CustodyWallet> wallets = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Transaction> transactions = new CopyOnWriteArrayList<>();

    public ExchangeService(QudoCryptoService qudo) { this.qudo = qudo; }

    public Map<String, String> createCustodyWallet(String name) throws Exception {
        var keys = qudo.generateKeyPair("ML-DSA-65");
        String id = "cw-" + UUID.randomUUID().toString().substring(0, 8);
        String addr = qudo.deriveAddress(keys.publicKeyPem());
        wallets.put(id, new CustodyWallet(id, name, addr, keys));
        return Map.of("walletId",id,"name",name,"address",addr,"algorithm","ML-DSA-65","publicKey",keys.publicKeyBase64());
    }

    public Map<String, String> deposit(String walletId, String amount, String asset) throws Exception { return processTx(walletId,"DEPOSIT",amount,asset); }
    public Map<String, String> withdraw(String walletId, String amount, String asset) throws Exception { return processTx(walletId,"WITHDRAW",amount,asset); }

    public Map<String, String> transfer(String fromId, String toId, String amount) throws Exception {
        var from = wallets.get(fromId); if (from==null) throw new IllegalArgumentException("Source not found");
        if (!wallets.containsKey(toId)) throw new IllegalArgumentException("Dest not found");
        String data = fromId+":"+toId+":"+amount+":"+System.currentTimeMillis();
        byte[] sig = qudo.sign(data.getBytes(), from.keys.privateKeyPem(), "ML-DSA-65");
        String txId = "tx-" + UUID.randomUUID().toString().substring(0, 8);
        transactions.add(new Transaction(txId,fromId,"TRANSFER",amount,"INTERNAL",Base64.getEncoder().encodeToString(sig),System.currentTimeMillis()));
        return Map.of("txId",txId,"from",fromId,"to",toId,"amount",amount,"algorithm","ML-DSA-65");
    }

    private Map<String, String> processTx(String walletId, String type, String amount, String asset) throws Exception {
        var w = wallets.get(walletId); if (w==null) throw new IllegalArgumentException("Wallet not found");
        String data = walletId+":"+type+":"+amount+":"+System.currentTimeMillis();
        byte[] sig = qudo.sign(data.getBytes(), w.keys.privateKeyPem(), "ML-DSA-65");
        String txId = "tx-" + UUID.randomUUID().toString().substring(0, 8);
        transactions.add(new Transaction(txId,walletId,type,amount,asset,Base64.getEncoder().encodeToString(sig),System.currentTimeMillis()));
        return Map.of("txId",txId,"walletId",walletId,"type",type,"amount",amount,"asset",asset,"algorithm","ML-DSA-65");
    }

    public List<Map<String, String>> listWallets() {
        return wallets.values().stream().map(w->Map.of("id",w.id,"name",w.name,"address",w.address,"algorithm","ML-DSA-65")).toList();
    }
    public List<Map<String, Object>> listTransactions() {
        return transactions.stream().map(t->Map.<String,Object>of(
            "id",t.id,"walletId",t.walletId,"type",t.type,"amount",t.amount,"asset",t.asset,
            "signature",t.signature,"timestamp",t.ts,"algorithm","ML-DSA-65")).toList();
    }
}
