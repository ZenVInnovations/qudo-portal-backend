package com.pqc;

import com.pqc.support.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Smoke test for the single sandbox surface that survives the per-service
 * teardown: PQC Primitives. Catches missing controller wiring or Spring
 * context startup regressions.
 *
 * <p>Per-service sandboxes (vpn / wallet / email / etc.) were intentionally
 * removed because they duplicated the same primitives in use-case-specific
 * envelopes. Migration content for those use cases lives in the docs.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class SandboxHealthTest {

    @Autowired TestRestTemplate rest;
    @LocalServerPort int port;

    @Test
    void primitivesSandboxHealthResponds() {
        String url = "http://localhost:" + port + "/api/v1/sandbox/primitives/health";
        ResponseEntity<String> response = rest.getForEntity(url, String.class);
        assertThat(response.getStatusCode().is2xxSuccessful())
                .as("expected 2xx, got %s with body=%s", response.getStatusCode(), response.getBody())
                .isTrue();
        assertThat(response.getBody()).contains("\"status\":\"UP\"");
        assertThat(response.getBody()).contains("\"service\":\"primitives-sandbox\"");
    }

    @Test
    void primitivesAlgorithmsCatalogReturnsExpectedFamilies() {
        String url = "http://localhost:" + port + "/api/v1/sandbox/primitives/algorithms";
        ResponseEntity<String> response = rest.getForEntity(url, String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        // Just enough shape assertion to catch a totally broken response;
        // exhaustive content tests live alongside the controller.
        assertThat(response.getBody()).contains("ML-DSA-65");
        assertThat(response.getBody()).contains("ML-KEM-768");
        assertThat(response.getBody()).contains("SLH-DSA");
    }

    @Test
    void actuatorHealthIsUp() {
        String url = "http://localhost:" + port + "/actuator/health";
        ResponseEntity<String> response = rest.getForEntity(url, String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("\"status\":\"UP\"");
    }
}
