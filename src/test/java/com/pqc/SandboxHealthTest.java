package com.pqc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Smoke test: hit every sandbox's {@code /health} endpoint and assert the BE
 * is wired correctly. Catches missing controllers, broken bean wiring, and
 * Spring context startup regressions in one pass.
 *
 * <p>Each sandbox's health endpoint is hand-written to return {@code status:
 * "UP"} (and usually some service-specific metadata). This test only checks
 * for HTTP 200 + non-null body — exhaustive shape assertions live alongside
 * the per-sandbox controller tests we'll add as we go.</p>
 */
class SandboxHealthTest extends AbstractIntegrationTest {

    @Autowired TestRestTemplate rest;
    @LocalServerPort int port;

    @ParameterizedTest(name = "sandbox /{0}/health responds with UP")
    @ValueSource(strings = {
            "vpn",
            "exchange",
            "dapp",
            "nft",
            "iot",
            "blockchain",
            "wallet",
            "defi",
            "rest-api",
            "signing",
            "ca",
            "email",
            "kms",
            "grpc",
    })
    void sandboxHealthEndpointResponds(String sandboxId) {
        String url = "http://localhost:" + port + "/api/v1/sandbox/" + sandboxId + "/health";
        ResponseEntity<String> response = rest.getForEntity(url, String.class);
        assertThat(response.getStatusCode().is2xxSuccessful())
                .as("sandbox=%s expected 2xx, got %s with body=%s", sandboxId, response.getStatusCode(), response.getBody())
                .isTrue();
        assertThat(response.getBody()).contains("\"status\"");
    }

    @org.junit.jupiter.api.Test
    void actuatorHealthIsUp() {
        String url = "http://localhost:" + port + "/actuator/health";
        ResponseEntity<String> response = rest.getForEntity(url, String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("\"status\":\"UP\"");
    }
}
