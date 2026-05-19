package com.pqc.sandbox.vpn;

import com.pqc.common.QudoCryptoService.KemEncapsulation;
import com.pqc.common.QudoCryptoService.KeyMaterial;
import jakarta.annotation.PostConstruct;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * VPN sandbox endpoints. Real ML-KEM-1024 / ML-DSA-65 operations via the
 * Qudo JNI provider. All routes under /api/v1/sandbox/vpn/** require an
 * authenticated session (gated in {@code SecurityConfig}).
 *
 * Ported verbatim from the old simulators/VpnGatewaySimulator with the URL
 * prefix moved under /api/v1/sandbox/vpn so the new BE owns the full sandbox
 * end-to-end with no external simulator service.
 */
@RestController
@RequestMapping("/api/v1/sandbox/vpn")
public class VpnSandboxController {

    private final VpnCryptoService crypto;

    private KeyMaterial gatewayKemKey;
    private KeyMaterial gatewayIdentityKey;

    private record Peer(String tunnelId, String name, KeyMaterial peerKemKey, String ipAddress, long registeredAt) {}
    private final ConcurrentHashMap<String, Peer> peers = new ConcurrentHashMap<>();

    private static class Session {
        final AtomicReference<byte[]> sessionKey = new AtomicReference<>();
        volatile long establishedAt;
        volatile long packetsIn;
        volatile long packetsOut;
        volatile long bytesIn;
        volatile long bytesOut;
        volatile int rekeyCount;
    }
    private final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();
    private final AtomicLong totalPackets = new AtomicLong();

    public VpnSandboxController(VpnCryptoService crypto) { this.crypto = crypto; }

    @PostConstruct
    public void init() throws Exception {
        this.gatewayKemKey = crypto.generateKemKeyPair();
        this.gatewayIdentityKey = crypto.generateIdentityKeyPair();
    }

    @GetMapping("/gateway-info")
    public ResponseEntity<?> gatewayInfo() {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "success");
        resp.put("gatewayName", "qudo-pqc-vpn-gw-01");
        resp.put("kemAlgorithm", VpnCryptoService.KEM_ALG);
        resp.put("identityAlgorithm", VpnCryptoService.SIG_ALG);
        resp.put("cipher", "AES-256-GCM");
        resp.put("gatewayKemPublicKey", new String(gatewayKemKey.publicKeyPem()));
        resp.put("gatewayIdentityPublicKey", new String(gatewayIdentityKey.publicKeyPem()));
        resp.put("activePeers", peers.size());
        resp.put("activeSessions", sessions.size());
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/register-peer")
    public ResponseEntity<?> registerPeer(@RequestBody Map<String, String> req) {
        try {
            String name = req.getOrDefault("name", "peer");
            String tunnelId = "tun-" + UUID.randomUUID().toString().substring(0, 8);
            long start = System.nanoTime();
            KeyMaterial peerKey = crypto.generateKemKeyPair();
            KeyMaterial peerIdentity = crypto.generateIdentityKeyPair();
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            String assignedIp = "10.42." + (peers.size() & 0xff) + "." + (1 + (peers.size() & 0x7f));
            peers.put(tunnelId, new Peer(tunnelId, name, peerKey, assignedIp, System.currentTimeMillis()));

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("status", "success");
            resp.put("tunnelId", tunnelId);
            resp.put("peerName", name);
            resp.put("assignedIp", assignedIp);
            resp.put("kemAlgorithm", VpnCryptoService.KEM_ALG);
            resp.put("identityAlgorithm", VpnCryptoService.SIG_ALG);
            resp.put("keyGenLatencyMs", elapsed);
            resp.put("peerKemPublicKey", new String(peerKey.publicKeyPem()));
            resp.put("peerIdentityPublicKey", new String(peerIdentity.publicKeyPem()));
            return ResponseEntity.ok(resp);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/handshake")
    public ResponseEntity<?> handshake(@RequestBody Map<String, String> req) {
        try {
            String tunnelId = req.get("tunnelId");
            Peer peer = peers.get(tunnelId);
            if (peer == null) {
                return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Tunnel not registered"));
            }

            long start = System.nanoTime();

            // Peer encapsulates to gateway's KEM public key.
            // In a real deployment the peer does this locally and only kemCiphertext goes on the wire.
            KemEncapsulation kem = crypto.encapsulate(gatewayKemKey.publicKeyPem());
            byte[] peerSharedSecret = kem.sharedSecret();

            // Gateway decapsulates — proves possession of its ML-KEM-1024 private key.
            byte[] gatewaySharedSecret = crypto.decapsulate(kem.ciphertext(), gatewayKemKey.privateKeyPem());

            boolean sharedSecretMatch = Arrays.equals(
                    Arrays.copyOf(peerSharedSecret, VpnCryptoService.AES_KEY_BYTES),
                    Arrays.copyOf(gatewaySharedSecret, VpnCryptoService.AES_KEY_BYTES));
            byte[] sessionKey = crypto.deriveAesKey(gatewaySharedSecret);

            // Gateway signs the transcript: tunnelId + KEM ciphertext + peer KEM pubkey hash.
            // Binds this handshake to this specific peer; prevents cross-peer transcript replay.
            String peerPubHash = hex(Arrays.copyOf(peer.peerKemKey.publicKeyPem(), 32));
            String transcriptStr = tunnelId + ":" +
                    Base64.getEncoder().encodeToString(kem.ciphertext()) + ":" + peerPubHash;
            byte[] transcript = transcriptStr.getBytes();
            byte[] handshakeSig = crypto.sign(transcript, gatewayIdentityKey.privateKeyPem());

            // Peer verifies gateway identity (prevents MITM swapping KEM pubkeys).
            boolean sigValid = crypto.verify(transcript, handshakeSig, gatewayIdentityKey.publicKeyPem());

            // Atomic key swap — old key zeroised.
            Session s = sessions.computeIfAbsent(tunnelId, k -> new Session());
            byte[] oldKey = s.sessionKey.getAndSet(sessionKey);
            if (oldKey != null) Arrays.fill(oldKey, (byte) 0);
            s.establishedAt = System.currentTimeMillis();

            long elapsed = (System.nanoTime() - start) / 1_000_000;

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("status", "success");
            resp.put("tunnelId", tunnelId);
            resp.put("kemAlgorithm", VpnCryptoService.KEM_ALG);
            resp.put("identityAlgorithm", VpnCryptoService.SIG_ALG);
            resp.put("cipher", "AES-256-GCM");
            resp.put("sessionKeyBits", sessionKey.length * 8);
            resp.put("sharedSecretMatch", sharedSecretMatch);
            resp.put("gatewayIdentityVerified", sigValid);
            resp.put("kemCiphertextBytes", kem.ciphertext().length);
            resp.put("handshakeSignatureBytes", handshakeSig.length);
            resp.put("handshakeSignature", Base64.getEncoder().encodeToString(handshakeSig));
            resp.put("transcript", transcriptStr);
            resp.put("gatewayIdentityPublicKey", new String(gatewayIdentityKey.publicKeyPem()));
            resp.put("handshakeLatencyMs", elapsed);
            resp.put("note", "Session established. Peer can verify gateway identity using the " +
                    "signature + transcript above. Use /send-packet to send encrypted traffic.");
            resp.put("simulatorNote", "This sandbox runs both sides (peer encapsulate + gateway decapsulate) " +
                    "in one call. In production, the peer runs encapsulate() locally and only sends " +
                    "kemCiphertext (1,568 bytes) over the wire to the gateway.");
            return ResponseEntity.ok(resp);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/send-packet")
    public ResponseEntity<?> sendPacket(@RequestBody Map<String, String> req) {
        try {
            String tunnelId = req.get("tunnelId");
            Session s = sessions.get(tunnelId);
            byte[] key = s != null ? s.sessionKey.get() : null;
            if (key == null) {
                return ResponseEntity.badRequest().body(Map.of("status", "error",
                        "message", "No active session. Call /handshake first."));
            }
            String payload = req.getOrDefault("payload", "ping from peer");
            int sizeBytes = 0;
            try { sizeBytes = Integer.parseInt(req.getOrDefault("size", "0")); } catch (NumberFormatException ignored) {}
            sizeBytes = Math.max(0, Math.min(sizeBytes, 65536));

            byte[] plaintext;
            if (sizeBytes > 0) {
                plaintext = new byte[sizeBytes];
                new java.security.SecureRandom().nextBytes(plaintext);
            } else {
                plaintext = payload.getBytes();
            }

            long start = System.nanoTime();

            byte[] ct = crypto.gcmEncrypt(key, plaintext);
            byte[] decrypted = crypto.gcmDecrypt(key, ct);
            String ack = sizeBytes > 0
                    ? "ack: received " + sizeBytes + " bytes"
                    : "ack: received \"" + new String(decrypted) + "\"";
            byte[] ackCt = crypto.gcmEncrypt(key, ack.getBytes());

            long elapsed = (System.nanoTime() - start) / 1_000_000;

            s.packetsIn++;
            s.packetsOut++;
            s.bytesIn += ct.length;
            s.bytesOut += ackCt.length;
            totalPackets.incrementAndGet();

            Map<String, Object> pktResp = new LinkedHashMap<>();
            pktResp.put("status", "success");
            pktResp.put("tunnelId", tunnelId);
            pktResp.put("plaintextBytes", plaintext.length);
            pktResp.put("payloadCiphertextBytes", ct.length);
            pktResp.put("gcmOverheadBytes", ct.length - plaintext.length);
            pktResp.put("ackPlaintext", ack);
            pktResp.put("ackCiphertextBytes", ackCt.length);
            pktResp.put("cipher", "AES-256-GCM");
            pktResp.put("latencyMs", elapsed);
            if (sizeBytes == 0) pktResp.put("payloadPlaintext", payload);
            return ResponseEntity.ok(pktResp);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/verify-handshake")
    public ResponseEntity<?> verifyHandshake(@RequestBody Map<String, String> req) {
        try {
            String signature = req.get("signature");
            String transcript = req.get("transcript");

            if (signature == null || transcript == null) {
                return ResponseEntity.badRequest().body(Map.of("status", "error",
                        "message", "Required fields: signature, transcript. Optional: gatewayIdentityPublicKey (defaults to this gateway's key)."));
            }

            // If client provides pubkey, use it. Otherwise use gateway's own — in the sandbox
            // both sides are this server; in production the peer would pin the gateway's pubkey.
            byte[] pubKey = req.containsKey("gatewayIdentityPublicKey")
                    ? req.get("gatewayIdentityPublicKey").getBytes()
                    : gatewayIdentityKey.publicKeyPem();

            long start = System.nanoTime();
            boolean valid = crypto.verify(
                    transcript.getBytes(),
                    Base64.getDecoder().decode(signature),
                    pubKey);
            long elapsed = (System.nanoTime() - start) / 1_000_000;

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "gatewayIdentityVerified", valid,
                    "algorithm", VpnCryptoService.SIG_ALG,
                    "verifyLatencyMs", elapsed,
                    "note", valid
                            ? "Gateway identity confirmed — this handshake was not tampered with."
                            : "SIGNATURE MISMATCH — possible MITM. Do not use this session."
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/rekey")
    public ResponseEntity<?> rekey(@RequestBody Map<String, String> req) {
        try {
            String tunnelId = req.get("tunnelId");
            Session s = sessions.get(tunnelId);
            if (s == null) {
                return ResponseEntity.badRequest().body(Map.of("status", "error",
                        "message", "No session. Call /handshake first."));
            }
            long start = System.nanoTime();

            KemEncapsulation kem = crypto.encapsulate(gatewayKemKey.publicKeyPem());
            byte[] sharedSecret = crypto.decapsulate(kem.ciphertext(), gatewayKemKey.privateKeyPem());
            byte[] newKey = crypto.deriveAesKey(sharedSecret);

            // Sign the rekey transcript so gateway identity stays consistent across rekey events.
            String transcriptStr = tunnelId + ":rekey:" +
                    Base64.getEncoder().encodeToString(kem.ciphertext());
            byte[] rekeySig = crypto.sign(transcriptStr.getBytes(), gatewayIdentityKey.privateKeyPem());
            boolean sigValid = crypto.verify(transcriptStr.getBytes(), rekeySig, gatewayIdentityKey.publicKeyPem());

            // Atomic key swap — old key zeroised.
            byte[] oldKey = s.sessionKey.getAndSet(newKey);
            if (oldKey != null) Arrays.fill(oldKey, (byte) 0);
            s.establishedAt = System.currentTimeMillis();
            s.rekeyCount++;

            long elapsed = (System.nanoTime() - start) / 1_000_000;

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("status", "success");
            resp.put("tunnelId", tunnelId);
            resp.put("rekeyCount", s.rekeyCount);
            resp.put("kemAlgorithm", VpnCryptoService.KEM_ALG);
            resp.put("identityAlgorithm", VpnCryptoService.SIG_ALG);
            resp.put("rekeySignatureVerified", sigValid);
            resp.put("rekeyLatencyMs", elapsed);
            resp.put("note", "Old session key zeroised. New key established with fresh ML-KEM-1024 encapsulation and signed by gateway identity.");
            return ResponseEntity.ok(resp);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/disconnect")
    public ResponseEntity<?> disconnect(@RequestBody Map<String, String> req) {
        String tunnelId = req.get("tunnelId");
        Session s = sessions.remove(tunnelId);
        if (s != null) {
            byte[] key = s.sessionKey.getAndSet(null);
            if (key != null) Arrays.fill(key, (byte) 0);
        }
        peers.remove(tunnelId);
        return ResponseEntity.ok(Map.of("status", "success", "tunnelId", tunnelId,
                "message", "Tunnel torn down, session key zeroised."));
    }

    @GetMapping("/tunnels")
    public ResponseEntity<?> listTunnels() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Peer p : peers.values()) {
            Session s = sessions.get(p.tunnelId);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("tunnelId", p.tunnelId);
            row.put("peerName", p.name);
            row.put("assignedIp", p.ipAddress);
            row.put("sessionActive", s != null && s.sessionKey.get() != null);
            if (s != null) {
                row.put("packetsIn", s.packetsIn);
                row.put("packetsOut", s.packetsOut);
                row.put("bytesIn", s.bytesIn);
                row.put("bytesOut", s.bytesOut);
                row.put("rekeyCount", s.rekeyCount);
            }
            list.add(row);
        }
        return ResponseEntity.ok(Map.of("tunnels", list, "count", list.size(),
                "totalPacketsForwarded", totalPackets.get()));
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "vpn-gateway-sandbox",
                "activePeers", peers.size(), "activeSessions", sessions.size()));
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }
}
