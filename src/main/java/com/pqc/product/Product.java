package com.pqc.product;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

/**
 * A product in the portal catalog. The backend is the source of truth for which
 * products are publicly visible; {@code enabled} + {@code visibility} drive that.
 *
 * <p>{@code productKey} is the stable external identifier (never the display
 * name) and is immutable once created.</p>
 */
@Entity
@Table(name = "products")
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "product_key", nullable = false, unique = true, updatable = false)
    private String productKey;

    @Column(nullable = false)
    private String name;

    @Column
    private String tagline;

    @Column(columnDefinition = "text")
    private String description;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "display_order", nullable = false)
    private int displayOrder = 0;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ProductVisibility visibility = ProductVisibility.PUBLIC;

    @Enumerated(EnumType.STRING)
    @Column(name = "product_type", nullable = false)
    private ProductType productType;

    @Enumerated(EnumType.STRING)
    @Column
    private ProductEdition edition;

    @Column(name = "documentation_url")
    private String documentationUrl;

    @Column(name = "repository_url")
    private String repositoryUrl;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected Product() {
        // for JPA
    }

    public Long getId() {
        return id;
    }

    public String getProductKey() {
        return productKey;
    }

    public void setProductKey(String productKey) {
        this.productKey = productKey;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getTagline() {
        return tagline;
    }

    public void setTagline(String tagline) {
        this.tagline = tagline;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getDisplayOrder() {
        return displayOrder;
    }

    public void setDisplayOrder(int displayOrder) {
        this.displayOrder = displayOrder;
    }

    public ProductVisibility getVisibility() {
        return visibility;
    }

    public void setVisibility(ProductVisibility visibility) {
        this.visibility = visibility;
    }

    public ProductType getProductType() {
        return productType;
    }

    public void setProductType(ProductType productType) {
        this.productType = productType;
    }

    public ProductEdition getEdition() {
        return edition;
    }

    public void setEdition(ProductEdition edition) {
        this.edition = edition;
    }

    public String getDocumentationUrl() {
        return documentationUrl;
    }

    public void setDocumentationUrl(String documentationUrl) {
        this.documentationUrl = documentationUrl;
    }

    public String getRepositoryUrl() {
        return repositoryUrl;
    }

    public void setRepositoryUrl(String repositoryUrl) {
        this.repositoryUrl = repositoryUrl;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
