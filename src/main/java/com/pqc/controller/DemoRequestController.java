package com.pqc.controller;

import com.pqc.common.QudoCryptoService;
import com.pqc.common.QudoCryptoService.KeyMaterial;
import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Demo-request endpoint. Public — no sign-in required. Every submission is
 * signed with ML-DSA-65 (FIPS 204) via the Qudo JNI provider before the
 * notification email is sent. The signature and public-key fingerprint ride
 * as MIME headers so the body stays readable while the notification remains
 * authenticable.
 *
 * Ported from ui-dashboard's DemoRequestController with the URL moved under
 * the new /api/v1/public/* namespace.
 */
@RestController
@RequestMapping("/api/v1/public/demo")
public class DemoRequestController {

    private static final Logger log = LoggerFactory.getLogger(DemoRequestController.class);
    private static final String SIG_ALG = "ML-DSA-65";

    private final JavaMailSender mailSender;
    private final QudoCryptoService qudo;
    private final CopyOnWriteArrayList<Map<String, String>> requests = new CopyOnWriteArrayList<>();
    private final ExecutorService mailExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "demo-mail-sender");
        t.setDaemon(true);
        return t;
    });

    @Value("${demo.notification.to:venkatesh.pulimamidi@zenv.ai}")
    private String notifyTo;

    @Value("${demo.notification.from:noreply@zenv.ai}")
    private String notifyFrom;

    @Value("${demo.notification.fromName:Qudo PQC (ZenV Quantum)}")
    private String notifyFromName;

    @Value("${demo.keys.dir:./keys}")
    private String keysDirPath;

    private volatile KeyMaterial signingKey;
    private volatile String signingPubFingerprint;

    public DemoRequestController(JavaMailSender mailSender, QudoCryptoService qudo) {
        this.mailSender = mailSender;
        this.qudo = qudo;
    }

    @PostConstruct
    public void initKeys() throws Exception {
        Path keysDir = Paths.get(keysDirPath);
        Files.createDirectories(keysDir);
        this.signingKey = loadOrGenerate(keysDir, "portal-signing-mldsa65", SIG_ALG);
        this.signingPubFingerprint = sha256Hex(signingKey.publicKeyPem());
        log.info("Demo-notification signing key ({}) ready. Pub SHA-256: {}",
                SIG_ALG, signingPubFingerprint);
    }

    private KeyMaterial loadOrGenerate(Path dir, String name, String alg) throws Exception {
        Path priv = dir.resolve(name + ".priv.pem");
        Path pub = dir.resolve(name + ".pub.pem");
        if (Files.exists(priv) && Files.exists(pub)) {
            return new KeyMaterial(alg, Files.readAllBytes(priv), Files.readAllBytes(pub));
        }
        KeyMaterial km = qudo.generateKeyPair(alg);
        Files.write(priv, km.privateKeyPem());
        Files.write(pub, km.publicKeyPem());
        try {
            Files.setPosixFilePermissions(priv,
                    java.util.EnumSet.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (Exception ignored) { /* non-POSIX FS */ }
        log.warn("Generated new {} keypair in {}.", alg, dir.toAbsolutePath());
        return km;
    }

    @PostMapping("/request")
    public ResponseEntity<?> submitRequest(@RequestBody Map<String, String> form) {
        String name = form.getOrDefault("name", "").trim();
        String email = form.getOrDefault("email", "").trim();
        String org = form.getOrDefault("organization", "").trim();
        // Optional free-text message. Caps at 500 chars — matches the
        // FE textarea cap and stops a paste-bomb from blowing up the
        // notification email payload.
        String message = form.getOrDefault("message", "").trim();
        if (message.length() > 500) message = message.substring(0, 500);

        List<String> errors = new ArrayList<>();
        if (name.isEmpty()) errors.add("Name is required");
        if (email.isEmpty() || !email.contains("@")) errors.add("Valid email is required");
        if (org.isEmpty()) errors.add("Organization is required");
        if (!errors.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "errors", errors));
        }

        String requestId = "demo-" + UUID.randomUUID().toString().substring(0, 8);
        String submittedAt = Instant.now().toString();
        Map<String, String> request = new LinkedHashMap<>();
        request.put("id", requestId);
        request.put("name", name);
        request.put("email", email);
        request.put("organization", org);
        request.put("message", message);
        request.put("submittedAt", submittedAt);
        request.put("status", "PENDING");
        requests.add(request);

        String canonical = canonicalize(request);
        String sigBase64 = null;
        try {
            byte[] sig = qudo.sign(canonical.getBytes(StandardCharsets.UTF_8),
                    signingKey.privateKeyPem(), SIG_ALG);
            sigBase64 = Base64.getEncoder().encodeToString(sig);
        } catch (Exception e) {
            log.warn("ML-DSA-65 signing failed for {}: {}", requestId, e.getMessage());
        }

        final String sigFinal = sigBase64;
        mailExecutor.submit(() -> sendNotification(request, sigFinal));

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "success");
        resp.put("message", "Demo request submitted. Our team will reach out within 24 hours.");
        resp.put("requestId", requestId);
        resp.put("signedWith", SIG_ALG);
        resp.put("signerPubSha256", signingPubFingerprint);
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/signing-pubkey")
    public ResponseEntity<?> signingPubKey() {
        if (signingKey == null) {
            return ResponseEntity.status(503).body(Map.of("status", "error", "message", "Not initialized"));
        }
        return ResponseEntity.ok(Map.of(
                "algorithm", SIG_ALG,
                "publicKeyPem", new String(signingKey.publicKeyPem(), StandardCharsets.UTF_8),
                "publicKeySha256", signingPubFingerprint,
                "note", "Verify signatures on X-Qudo-Signature email headers with this key."
        ));
    }

    private void sendNotification(Map<String, String> request, String sigBase64) {
        try {
            MimeMessage mime = mailSender.createMimeMessage();
            MimeMessageHelper m = new MimeMessageHelper(mime, false, "UTF-8");
            m.setTo(notifyTo);
            m.setFrom(notifyFrom, notifyFromName);
            String fromName = request.get("name");
            String fromEmail = request.get("email");
            String org = request.get("organization");
            String message = request.getOrDefault("message", "");
            if (!fromEmail.isEmpty()) m.setReplyTo(fromEmail);

            m.setSubject("New demo request — " + fromName + " @ " + org);

            // Re-format the canonical ISO timestamp into something a
            // human reading the email at 10pm can scan at a glance.
            // Source IST because both the inbox and the requester are
            // typically in that timezone; we also keep the UTC form for
            // anyone correlating across time zones.
            String humanWhen;
            try {
                ZonedDateTime ist = Instant.parse(request.get("submittedAt"))
                        .atZone(ZoneId.of("Asia/Kolkata"));
                humanWhen = ist.format(DateTimeFormatter.ofPattern("d MMM yyyy, h:mm a 'IST'"))
                        + "   (" + request.get("submittedAt") + ")";
            } catch (Exception parseFailed) {
                humanWhen = request.get("submittedAt");
            }

            StringBuilder body = new StringBuilder();
            body.append("Demo request from ").append(fromName)
                .append(" (").append(org).append(").\n\n");
            body.append("Reply to this email to reach the customer directly.\n\n");
            body.append("  Name          ").append(fromName).append('\n');
            body.append("  Email         ").append(fromEmail).append('\n');
            body.append("  Organization  ").append(org).append('\n');
            body.append("  Submitted     ").append(humanWhen).append('\n');
            body.append("  Request ID    ").append(request.get("id")).append('\n');
            if (!message.isEmpty()) {
                body.append('\n').append("Message:\n").append(message).append('\n');
            }
            m.setText(body.toString());

            if (sigBase64 != null) {
                mime.setHeader("X-Qudo-Signature-Alg", SIG_ALG);
                mime.setHeader("X-Qudo-Signature", sigBase64);
                mime.setHeader("X-Qudo-PubKey-SHA256", signingPubFingerprint);
            }

            mailSender.send(mime);
            log.info("PQC-signed demo notification sent to {} for {}", notifyTo, request.get("id"));
        } catch (Exception e) {
            log.warn("Failed to send demo notification: {}. Request {} still saved.",
                    e.getMessage(), request.get("id"));
        }
    }

    private static String canonicalize(Map<String, String> req) {
        // Keys signed by the ML-DSA-65 notification signature. Adding /
        // removing a field here changes the signature surface, so any
        // verifier of the X-Qudo-Signature header must use the SAME key
        // list. `description` was renamed to `message` on 2026-05-21 in
        // sync with the FE form rename.
        String[] keys = {"id", "email", "name", "organization", "submittedAt", "message"};
        Arrays.sort(keys);
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < keys.length; i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(keys[i]).append("\":\"")
              .append(escape(req.getOrDefault(keys[i], ""))).append('"');
        }
        return sb.append('}').toString();
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "unknown";
        }
    }
}
