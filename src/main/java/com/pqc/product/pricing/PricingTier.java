package com.pqc.product.pricing;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

/**
 * A commercial support-subscription pricing tier. Prices are proposed and change,
 * so they are held here and edited through the Admin Portal rather than baked
 * into the frontend.
 *
 * <p>{@code tierKey} is the stable external identifier (never the display name)
 * and is immutable once created. {@code priceVisible} controls whether the public
 * API returns the amount; the amount itself is always retained so toggling
 * visibility never loses the figure.</p>
 */
@Entity
@Table(name = "pricing_tiers")
public class PricingTier {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tier_key", nullable = false, unique = true, updatable = false)
    private String tierKey;

    @Column(nullable = false)
    private String name;

    @Column
    private String audience;

    /** Annual price in the currency's major unit (whole dollars); null = unset. */
    @Column(name = "price_amount")
    private Long priceAmount;

    @Column(nullable = false)
    private String currency = "USD";

    @Column(name = "price_visible", nullable = false)
    private boolean priceVisible = true;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private boolean highlighted = false;

    @Column(name = "display_order", nullable = false)
    private int displayOrder = 0;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected PricingTier() {
        // for JPA
    }

    public Long getId() {
        return id;
    }

    public String getTierKey() {
        return tierKey;
    }

    public void setTierKey(String tierKey) {
        this.tierKey = tierKey;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public Long getPriceAmount() {
        return priceAmount;
    }

    public void setPriceAmount(Long priceAmount) {
        this.priceAmount = priceAmount;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }

    public boolean isPriceVisible() {
        return priceVisible;
    }

    public void setPriceVisible(boolean priceVisible) {
        this.priceVisible = priceVisible;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isHighlighted() {
        return highlighted;
    }

    public void setHighlighted(boolean highlighted) {
        this.highlighted = highlighted;
    }

    public int getDisplayOrder() {
        return displayOrder;
    }

    public void setDisplayOrder(int displayOrder) {
        this.displayOrder = displayOrder;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
