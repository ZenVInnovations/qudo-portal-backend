package com.pqc.product;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises the real schema + Flyway seed against a real Postgres (Testcontainers).
 * No native crypto lib is loaded — this slice never touches QudoCryptoService.
 *
 * <p>{@code disabledWithoutDocker = true}: the class is skipped when no usable
 * Docker daemon is detected, so it never fails a build on a machine without one;
 * it runs in CI and any standard Docker environment. (The migration SQL is also
 * validated directly against the docker-compose Postgres.)</p>
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
class ProductRepositoryTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired
    ProductRepository repo;

    @Test
    void seedCreatesFourProductsInOrder() {
        assertThat(repo.findAllByOrderByDisplayOrderAsc())
                .extracting(Product::getProductKey)
                .containsExactly("qudossl-community", "qudossl-commercial", "qudoprovider", "qudopqc");
    }

    @Test
    void publicQueryReturnsOnlyEnabledPublicProductsInOrder() {
        List<Product> publicProducts =
                repo.findByEnabledTrueAndVisibilityOrderByDisplayOrderAsc(ProductVisibility.PUBLIC);

        assertThat(publicProducts)
                .extracting(Product::getProductKey)
                .containsExactly("qudossl-community", "qudossl-commercial");

        // The parked products are disabled and must never surface publicly.
        assertThat(publicProducts)
                .extracting(Product::getProductKey)
                .doesNotContain("qudoprovider", "qudopqc");
    }
}
