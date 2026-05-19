package com.pqc.sandbox.kms;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class Pkcs11SimulatorService {
    public record Token(String label, String pin, List<String> keyIds, boolean initialized) {}
    private final ConcurrentHashMap<String, Token> tokens = new ConcurrentHashMap<>();

    public Map<String, String> initToken(String label, String pin) {
        tokens.put(label, new Token(label, pin, new ArrayList<>(), true));
        return Map.of("label", label, "status", "initialized");
    }

    public Map<String, String> storeKey(String label, String keyId) {
        Token t = tokens.get(label);
        if (t == null) throw new IllegalArgumentException("Token not found: " + label);
        t.keyIds().add(keyId);
        return Map.of("label", label, "keyId", keyId, "status", "stored");
    }

    public Map<String, Object> retrieveKey(String label, String keyId) {
        Token t = tokens.get(label);
        if (t == null) throw new IllegalArgumentException("Token not found");
        boolean found = t.keyIds().contains(keyId);
        return Map.of("label", label, "keyId", keyId, "found", found);
    }
}
