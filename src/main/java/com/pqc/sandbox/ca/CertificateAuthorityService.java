package com.pqc.sandbox.ca;

import com.pqc.common.QudoCryptoService;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PQC Certificate Authority sandbox.
 * Creates Root CA, Intermediate CA, and end-entity certificates using
 * ML-DSA via the Qudo JNI provider.
 */
@Service
public class CertificateAuthorityService {

    private final QudoCryptoService qudo;

    private final ConcurrentHashMap<String, byte[]> privateKeys = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, byte[]> certificates = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Map<String, String>> certMetadata = new ConcurrentHashMap<>();

    public CertificateAuthorityService(QudoCryptoService qudo) { this.qudo = qudo; }

    public Map<String, Object> createRootCA(String algorithm, String subject) throws Exception {
        String id = "root-" + UUID.randomUUID().toString().substring(0, 8);
        QudoCryptoService.KeyMaterial keys = qudo.generateKeyPair(algorithm);
        byte[] cert = qudo.createSelfSignedCert(keys.privateKeyPem(),
                "/CN=" + subject + "/O=Qudo Portal/OU=Root CA/C=US", 3650);
        privateKeys.put(id, keys.privateKeyPem());
        certificates.put(id, cert);
        certMetadata.put(id, Map.of("id", id, "subject", subject, "algorithm", algorithm,
                "type", "ROOT_CA", "issuer", subject, "validDays", "3650"));

        Map<String, String> details = parseCertificate(cert);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", id);
        result.put("subject", subject);
        result.put("algorithm", algorithm);
        result.put("type", "ROOT_CA");
        result.put("validDays", 3650);
        result.put("certificate", Base64.getEncoder().encodeToString(cert));
        result.put("details", details);
        return result;
    }

    public Map<String, Object> createIntermediateCA(String algorithm, String subject, String rootCaId) throws Exception {
        byte[] rootKey = privateKeys.get(rootCaId);
        byte[] rootCert = certificates.get(rootCaId);
        if (rootKey == null || rootCert == null) {
            throw new IllegalArgumentException("Root CA not found: " + rootCaId);
        }
        String id = "intermediate-" + UUID.randomUUID().toString().substring(0, 8);
        QudoCryptoService.KeyMaterial keys = qudo.generateKeyPair(algorithm);
        byte[] csr = qudo.createCSR(keys.privateKeyPem(),
                "/CN=" + subject + "/O=Qudo Portal/OU=Intermediate CA/C=US");
        byte[] cert = qudo.signCSR(csr, rootKey, rootCert, 1825);

        privateKeys.put(id, keys.privateKeyPem());
        certificates.put(id, cert);
        certMetadata.put(id, Map.of("id", id, "subject", subject, "algorithm", algorithm,
                "type", "INTERMEDIATE_CA", "issuer", certMetadata.get(rootCaId).get("subject"),
                "rootCaId", rootCaId, "validDays", "1825"));

        Map<String, String> details = parseCertificate(cert);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", id);
        result.put("subject", subject);
        result.put("algorithm", algorithm);
        result.put("type", "INTERMEDIATE_CA");
        result.put("rootCaId", rootCaId);
        result.put("validDays", 1825);
        result.put("certificate", Base64.getEncoder().encodeToString(cert));
        result.put("details", details);
        return result;
    }

    public Map<String, Object> signCSR(String subject, String signerCaId, String algorithm) throws Exception {
        byte[] signerKey = privateKeys.get(signerCaId);
        byte[] signerCert = certificates.get(signerCaId);
        if (signerKey == null || signerCert == null) {
            throw new IllegalArgumentException("Signer CA not found: " + signerCaId);
        }
        String id = "cert-" + UUID.randomUUID().toString().substring(0, 8);
        QudoCryptoService.KeyMaterial keys = qudo.generateKeyPair(algorithm);
        byte[] csr = qudo.createCSR(keys.privateKeyPem(),
                "/CN=" + subject + "/O=Qudo Portal/OU=End Entity/C=US");
        byte[] cert = qudo.signCSR(csr, signerKey, signerCert, 365);

        certificates.put(id, cert);
        certMetadata.put(id, Map.of("id", id, "subject", subject, "algorithm", algorithm,
                "type", "END_ENTITY", "issuer", certMetadata.get(signerCaId).get("subject"),
                "signerCaId", signerCaId, "validDays", "365"));

        Map<String, String> details = parseCertificate(cert);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", id);
        result.put("subject", subject);
        result.put("algorithm", algorithm);
        result.put("type", "END_ENTITY");
        result.put("signerCaId", signerCaId);
        result.put("validDays", 365);
        result.put("certificate", Base64.getEncoder().encodeToString(cert));
        result.put("details", details);
        return result;
    }

    public Map<String, Object> createHybridCertificate(String subject, String pqcAlgorithm) throws Exception {
        QudoCryptoService.KeyMaterial ecKeys = qudo.generateKeyPair("EC");
        byte[] ecCert = qudo.createSelfSignedCert(ecKeys.privateKeyPem(),
                "/CN=" + subject + " (ECDSA)/O=Qudo Portal/OU=Hybrid/C=US", 365);

        QudoCryptoService.KeyMaterial pqcKeys = qudo.generateKeyPair(pqcAlgorithm);
        byte[] pqcCert = qudo.createSelfSignedCert(pqcKeys.privateKeyPem(),
                "/CN=" + subject + " (PQC)/O=Qudo Portal/OU=Hybrid/C=US", 365);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("subject", subject);
        result.put("type", "HYBRID");
        result.put("ecdsaCertificate", Base64.getEncoder().encodeToString(ecCert));
        result.put("ecdsaAlgorithm", "ECDSA P-384");
        result.put("ecdsaDetails", parseCertificate(ecCert));
        result.put("pqcCertificate", Base64.getEncoder().encodeToString(pqcCert));
        result.put("pqcAlgorithm", pqcAlgorithm);
        result.put("pqcDetails", parseCertificate(pqcCert));
        return result;
    }

    public Map<String, Object> getCertificateChain() {
        List<Map<String, Object>> chain = new ArrayList<>();
        certMetadata.forEach((id, meta) -> {
            Map<String, Object> entry = new LinkedHashMap<>(meta);
            entry.put("hasCertificate", certificates.containsKey(id));
            chain.add(entry);
        });
        return Map.of("certificates", chain, "count", chain.size());
    }

    public Map<String, Object> inspectCertificate(String certId) {
        byte[] cert = certificates.get(certId);
        if (cert == null) throw new IllegalArgumentException("Certificate not found: " + certId);
        Map<String, String> details = parseCertificate(cert);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", certId);
        result.putAll(certMetadata.getOrDefault(certId, Map.of()));
        result.put("details", details);
        result.put("pem", new String(cert));
        return result;
    }

    public List<String> getSupportedAlgorithms() {
        return List.of("ML-DSA-44", "ML-DSA-65", "ML-DSA-87");
    }

    private Map<String, String> parseCertificate(byte[] certPem) {
        Map<String, String> details = new LinkedHashMap<>();
        try {
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
                    cf.generateCertificate(new java.io.ByteArrayInputStream(certPem));
            details.put("subject", cert.getSubjectX500Principal().getName());
            details.put("issuer", cert.getIssuerX500Principal().getName());
            details.put("notBefore", cert.getNotBefore().toString());
            details.put("notAfter", cert.getNotAfter().toString());
            details.put("serial", cert.getSerialNumber().toString(16));
            details.put("signatureAlgorithm", cert.getSigAlgName());
        } catch (Exception e) {
            details.put("parseNote", "Certificate generated by Qudo JNI using PQC algorithms. " +
                    "Standard Java X.509 parser may not recognize PQC OIDs — use OpenSSL 3.6+ for full inspection.");
            details.put("pemAvailable", "true");
        }
        return details;
    }
}
