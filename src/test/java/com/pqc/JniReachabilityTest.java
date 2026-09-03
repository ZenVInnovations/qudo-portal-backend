package com.pqc;

import com.pqc.common.QudoCryptoService;
import com.pqc.support.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the Qudo JNI native library is reachable from the test JVM and that
 * basic ML-DSA-65 sign+verify works. If this fails, every sandbox test will
 * also fail — start here when debugging CI.
 *
 * <p>Surefire passes {@code -Djava.library.path=${qudo.native.lib.path}} (set
 * in pom.xml) so the native lib is discoverable.</p>
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class JniReachabilityTest {

    @Autowired
    QudoCryptoService qudo;

    @Test
    void mlDsa65SignAndVerifyRoundtrip() throws Exception {
        byte[] data = "qudo-smoke-test".getBytes();

        QudoCryptoService.KeyMaterial keys = qudo.generateKeyPair("ML-DSA-65");
        assertThat(keys.privateKeyPem()).isNotEmpty();
        assertThat(keys.publicKeyPem()).isNotEmpty();

        byte[] sig = qudo.sign(data, keys.privateKeyPem(), "ML-DSA-65");
        assertThat(sig).isNotEmpty();

        boolean valid = qudo.verify(data, sig, keys.publicKeyPem(), "ML-DSA-65");
        assertThat(valid).isTrue();

        // Negative: flipping a byte in the data must fail verification.
        byte[] tampered = data.clone();
        tampered[0] ^= 0x01;
        assertThat(qudo.verify(tampered, sig, keys.publicKeyPem(), "ML-DSA-65")).isFalse();
    }

    @Test
    void mlKem768EncapDecapRoundtrip() throws Exception {
        QudoCryptoService.KeyMaterial keys = qudo.generateKeyPair("ML-KEM-768");

        QudoCryptoService.KemEncapsulation encap = qudo.kemEncapsulate(keys.publicKeyPem(), "ML-KEM-768");
        byte[] secretAtSender = encap.sharedSecret();

        byte[] secretAtRecipient = qudo.kemDecapsulate(encap.ciphertext(), keys.privateKeyPem(), "ML-KEM-768");

        // The whole point of ML-KEM: both sides derive the same secret.
        assertThat(secretAtSender).isEqualTo(secretAtRecipient);
    }
}
