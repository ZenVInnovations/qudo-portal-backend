package com.pqc.sandbox.ca;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/sandbox/ca")
public class CaSandboxController {

    private final CertificateAuthorityService caService;

    public CaSandboxController(CertificateAuthorityService caService) { this.caService = caService; }

    @PostMapping("/create-root")
    public ResponseEntity<?> createRootCA(@RequestBody Map<String, String> request) {
        try {
            String algorithm = request.getOrDefault("algorithm", "ML-DSA-65");
            String subject = request.getOrDefault("subject", "PQC Root CA");
            long start = System.nanoTime();
            var result = caService.createRootCA(algorithm, subject);
            return ResponseEntity.ok(Map.of("status", "success", "rootCA", result, "latencyMs", (System.nanoTime() - start) / 1_000_000));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/create-intermediate")
    public ResponseEntity<?> createIntermediateCA(@RequestBody Map<String, String> request) {
        try {
            String algorithm = request.getOrDefault("algorithm", "ML-DSA-65");
            String subject = request.getOrDefault("subject", "PQC Intermediate CA");
            String rootCaId = request.get("rootCaId");
            long start = System.nanoTime();
            var result = caService.createIntermediateCA(algorithm, subject, rootCaId);
            return ResponseEntity.ok(Map.of("status", "success", "intermediateCA", result, "latencyMs", (System.nanoTime() - start) / 1_000_000));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/issue-cert")
    public ResponseEntity<?> issueCertificate(@RequestBody Map<String, String> request) {
        try {
            String subject = request.getOrDefault("subject", "PQC End Entity");
            String signerCaId = request.get("signerCaId");
            String algorithm = request.getOrDefault("algorithm", "ML-DSA-65");
            long start = System.nanoTime();
            var result = caService.signCSR(subject, signerCaId, algorithm);
            return ResponseEntity.ok(Map.of("status", "success", "certificate", result, "latencyMs", (System.nanoTime() - start) / 1_000_000));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/create-hybrid")
    public ResponseEntity<?> createHybridCertificate(@RequestBody Map<String, String> request) {
        try {
            String subject = request.getOrDefault("subject", "PQC Hybrid Certificate");
            String pqcAlgorithm = request.getOrDefault("algorithm", "ML-DSA-65");
            long start = System.nanoTime();
            var result = caService.createHybridCertificate(subject, pqcAlgorithm);
            return ResponseEntity.ok(Map.of("status", "success", "hybridCert", result, "latencyMs", (System.nanoTime() - start) / 1_000_000));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @GetMapping("/chain")
    public ResponseEntity<?> getCertificateChain() {
        return ResponseEntity.ok(Map.of("status", "success", "chain", caService.getCertificateChain()));
    }

    @GetMapping("/inspect/{certId}")
    public ResponseEntity<?> inspectCertificate(@PathVariable String certId) {
        try {
            return ResponseEntity.ok(Map.of("status", "success", "certificate", caService.inspectCertificate(certId)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/inspect-pem")
    public ResponseEntity<?> inspectPem(@RequestBody Map<String, String> request) {
        try {
            String pem = request.get("pem");
            return ResponseEntity.ok(Map.of("status", "success", "inspection", caService.inspectPem(pem)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @GetMapping("/algorithms")
    public ResponseEntity<?> getAlgorithms() {
        return ResponseEntity.ok(Map.of(
                "algorithms", caService.getSupportedAlgorithms(),
                "note", "CA sandbox uses ML-DSA for certificate signing. ML-KEM is not used for PKI.",
                "service", "ca-sandbox", "provider", "Qudo Cryptographic Module"));
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "ca-sandbox",
                "supportedAlgorithms", caService.getSupportedAlgorithms()));
    }
}
