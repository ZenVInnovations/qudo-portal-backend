package com.pqc.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The single administrator credential for the product-management API. Supplied
 * via env (ADMIN_USERNAME / ADMIN_PASSWORD_HASH) — the password is a BCrypt hash,
 * never plaintext, and is never committed. {@code dev}/{@code prod} fail closed
 * if either is blank; the {@code local} profile ships a dev-only default.
 */
@ConfigurationProperties("app.admin")
public class AdminAuthProperties {

    private String username;
    private String passwordHash;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }
}
