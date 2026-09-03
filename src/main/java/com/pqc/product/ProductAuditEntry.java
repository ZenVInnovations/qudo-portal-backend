package com.pqc.product;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

/**
 * One immutable audit record per changed field on an admin product mutation:
 * who changed what, from what, to what, and when.
 */
@Entity
@Table(name = "product_audit")
public class ProductAuditEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "product_key", nullable = false)
    private String productKey;

    @Column(name = "admin_username", nullable = false)
    private String adminUsername;

    @Column(name = "field_changed", nullable = false)
    private String fieldChanged;

    @Column(name = "old_value")
    private String oldValue;

    @Column(name = "new_value")
    private String newValue;

    @CreationTimestamp
    @Column(name = "changed_at", nullable = false, updatable = false)
    private Instant changedAt;

    protected ProductAuditEntry() {
        // for JPA
    }

    public ProductAuditEntry(String productKey, String adminUsername, String fieldChanged,
                             String oldValue, String newValue) {
        this.productKey = productKey;
        this.adminUsername = adminUsername;
        this.fieldChanged = fieldChanged;
        this.oldValue = oldValue;
        this.newValue = newValue;
    }

    public Long getId() {
        return id;
    }

    public String getProductKey() {
        return productKey;
    }

    public String getAdminUsername() {
        return adminUsername;
    }

    public String getFieldChanged() {
        return fieldChanged;
    }

    public String getOldValue() {
        return oldValue;
    }

    public String getNewValue() {
        return newValue;
    }

    public Instant getChangedAt() {
        return changedAt;
    }
}
