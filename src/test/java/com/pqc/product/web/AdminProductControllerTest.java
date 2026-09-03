package com.pqc.product.web;

import com.pqc.config.SecurityConfig;
import com.pqc.product.ProductNotFoundException;
import com.pqc.product.ProductService;
import com.pqc.product.dto.AdminProductDto;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Authorization + validation for the admin product API. The admin filter chain
 * requires an authenticated ROLE_ADMIN session and CSRF on mutations.
 */
@WebMvcTest(AdminProductController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
class AdminProductControllerTest {

    @Autowired
    MockMvc mvc;

    @MockBean
    ProductService service;

    private AdminProductDto dto() {
        return new AdminProductDto(1L, "qudossl-community", "QudoSSL Community Edition", "tag", "desc",
                false, 1, "PUBLIC", "QUDOSSL_EDITION", "COMMUNITY",
                "/products/qudossl-community", null, Instant.now(), Instant.now());
    }

    @Test
    void unauthenticatedRequestIsUnauthorized() throws Exception {
        mvc.perform(get("/api/v1/admin/products"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "USER")
    void nonAdminIsForbidden() throws Exception {
        mvc.perform(get("/api/v1/admin/products"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminCanListProducts() throws Exception {
        when(service.getAllProducts()).thenReturn(List.of(dto()));
        mvc.perform(get("/api/v1/admin/products"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    void adminCanToggleProduct() throws Exception {
        when(service.updateProduct(eq(1L), any(), any())).thenReturn(dto());
        mvc.perform(put("/api/v1/admin/products/1")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void invalidVisibilityIsBadRequest() throws Exception {
        mvc.perform(put("/api/v1/admin/products/1")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"visibility\":\"BOGUS\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void unknownIdIsNotFound() throws Exception {
        when(service.updateProduct(eq(99L), any(), any())).thenThrow(new ProductNotFoundException(99L));
        mvc.perform(put("/api/v1/admin/products/99")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void mutationWithoutCsrfIsForbidden() throws Exception {
        mvc.perform(put("/api/v1/admin/products/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isForbidden());
    }
}
