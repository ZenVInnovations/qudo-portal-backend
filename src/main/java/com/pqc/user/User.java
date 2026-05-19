package com.pqc.user;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users", uniqueConstraints = @UniqueConstraint(
        name = "users_provider_subject_uk", columnNames = {"provider", "provider_subject"}))
public class User {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "email", nullable = false, length = 320)
    private String email;

    @Column(name = "name", length = 255)
    private String name;

    @Column(name = "picture_url", length = 1024)
    private String pictureUrl;

    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified;

    @Column(name = "provider", nullable = false, length = 64)
    private String provider;

    @Column(name = "provider_subject", nullable = false, length = 255)
    private String providerSubject;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_login_at", nullable = false)
    private Instant lastLoginAt;

    @Column(name = "login_count", nullable = false)
    private int loginCount;

    protected User() {}

    public User(UUID id, String email, String name, String pictureUrl, boolean emailVerified,
                String provider, String providerSubject) {
        this.id = id;
        this.email = email;
        this.name = name;
        this.pictureUrl = pictureUrl;
        this.emailVerified = emailVerified;
        this.provider = provider;
        this.providerSubject = providerSubject;
        this.createdAt = Instant.now();
        this.lastLoginAt = this.createdAt;
        this.loginCount = 1;
    }

    public void recordLogin(String email, String name, String pictureUrl, boolean emailVerified) {
        this.email = email;
        this.name = name;
        this.pictureUrl = pictureUrl;
        this.emailVerified = emailVerified;
        this.lastLoginAt = Instant.now();
        this.loginCount++;
    }

    public UUID getId() { return id; }
    public String getEmail() { return email; }
    public String getName() { return name; }
    public String getPictureUrl() { return pictureUrl; }
    public boolean isEmailVerified() { return emailVerified; }
    public String getProvider() { return provider; }
    public String getProviderSubject() { return providerSubject; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastLoginAt() { return lastLoginAt; }
    public int getLoginCount() { return loginCount; }
}
