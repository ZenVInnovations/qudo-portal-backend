package com.pqc.product.web;

import com.pqc.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Login lifecycle. Also validates that the BCrypt hash used for the test/dev
 * admin actually verifies with Spring's BCryptPasswordEncoder (the same hash the
 * `local` profile ships), so a green run here means the dev default works too.
 * Credentials come from application-test.yml: test-admin / qudo-admin-dev.
 */
@WebMvcTest(AdminAuthController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
class AdminAuthControllerTest {

    @Autowired
    MockMvc mvc;

    @Test
    void loginWithCorrectCredentialsSucceeds() throws Exception {
        mvc.perform(post("/api/v1/admin/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"test-admin\",\"password\":\"qudo-admin-dev\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("test-admin"));
    }

    @Test
    void loginWithWrongPasswordIsUnauthorized() throws Exception {
        mvc.perform(post("/api/v1/admin/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"test-admin\",\"password\":\"not-the-password\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginWithoutCsrfIsForbidden() throws Exception {
        mvc.perform(post("/api/v1/admin/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"test-admin\",\"password\":\"qudo-admin-dev\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void meWithoutAuthenticationIsUnauthorized() throws Exception {
        mvc.perform(get("/api/v1/admin/me"))
                .andExpect(status().isUnauthorized());
    }
}
