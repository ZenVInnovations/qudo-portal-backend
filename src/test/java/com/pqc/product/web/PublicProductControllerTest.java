package com.pqc.product.web;

import com.pqc.config.SecurityConfig;
import com.pqc.product.ProductService;
import com.pqc.product.dto.PublicProductDto;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The public products endpoint is served by the permit-all chain and returns the
 * minimal public DTO. Verifies the JSON shape and that internal fields never leak.
 */
@WebMvcTest(PublicProductController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
class PublicProductControllerTest {

    @Autowired
    MockMvc mvc;

    @MockBean
    ProductService service;

    @Test
    void returnsPublicProductsWithoutInternalFields() throws Exception {
        when(service.getPublicProducts()).thenReturn(List.of(
                new PublicProductDto("qudossl-community", "QudoSSL Community Edition",
                        "Free, open-source post-quantum TLS.", 1, "QUDOSSL_EDITION", "COMMUNITY",
                        "/products/qudossl-community", "https://github.com/ZenVInnovations/qudossl")));

        mvc.perform(get("/api/v1/public/products"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].key").value("qudossl-community"))
                .andExpect(jsonPath("$[0].name").value("QudoSSL Community Edition"))
                .andExpect(jsonPath("$[0].edition").value("COMMUNITY"))
                // internal fields are never exposed on the public API
                .andExpect(jsonPath("$[0].enabled").doesNotExist())
                .andExpect(jsonPath("$[0].visibility").doesNotExist())
                .andExpect(jsonPath("$[0].id").doesNotExist());
    }
}
