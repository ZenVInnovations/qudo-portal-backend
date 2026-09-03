package com.pqc.product.pricing;

import com.pqc.product.ProductAuditEntry;
import com.pqc.product.ProductAuditRepository;
import com.pqc.product.pricing.dto.AdminPricingTierDto;
import com.pqc.product.pricing.dto.PublicPricingTierDto;
import com.pqc.product.pricing.dto.UpdatePricingTierRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Pricing-tier operations. Public reads return only enabled tiers, with each
 * tier's price shown or withheld per its {@code priceVisible} flag. Admin updates
 * are applied field-by-field, writing one audit row per actually-changed field.
 *
 * <p>Reuses the shared {@code product_audit} trail with a {@code pricing:<tierKey>}
 * key namespace, so pricing changes get the same immutable who/what/when record
 * as product-visibility changes.</p>
 */
@Service
public class PricingService {

    /** Audit-key prefix so pricing rows don't collide with product rows. */
    private static final String AUDIT_KEY_PREFIX = "pricing:";

    private final PricingTierRepository tiers;
    private final ProductAuditRepository audit;

    public PricingService(PricingTierRepository tiers, ProductAuditRepository audit) {
        this.tiers = tiers;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<PublicPricingTierDto> getPublicTiers() {
        return tiers.findByEnabledTrueOrderByDisplayOrderAsc()
                .stream().map(PricingMapper::toPublic).toList();
    }

    @Transactional(readOnly = true)
    public List<AdminPricingTierDto> getAllTiers() {
        return tiers.findAllByOrderByDisplayOrderAsc()
                .stream().map(PricingMapper::toAdmin).toList();
    }

    @Transactional
    public AdminPricingTierDto updateTier(Long id, UpdatePricingTierRequest req, String adminUsername) {
        PricingTier t = tiers.findById(id).orElseThrow(() -> new PricingTierNotFoundException(id));
        String key = AUDIT_KEY_PREFIX + t.getTierKey();

        if (req.name() != null) {
            change(key, adminUsername, "name", t.getName(), req.name(), v -> t.setName(req.name()));
        }
        if (req.audience() != null) {
            change(key, adminUsername, "audience", t.getAudience(), req.audience(), v -> t.setAudience(req.audience()));
        }
        if (req.priceAmount() != null) {
            change(key, adminUsername, "priceAmount",
                    String.valueOf(t.getPriceAmount()), String.valueOf(req.priceAmount()),
                    v -> t.setPriceAmount(req.priceAmount()));
        }
        if (req.currency() != null) {
            change(key, adminUsername, "currency", t.getCurrency(), req.currency(), v -> t.setCurrency(req.currency()));
        }
        if (req.priceVisible() != null) {
            change(key, adminUsername, "priceVisible",
                    String.valueOf(t.isPriceVisible()), String.valueOf(req.priceVisible()),
                    v -> t.setPriceVisible(req.priceVisible()));
        }
        if (req.enabled() != null) {
            change(key, adminUsername, "enabled",
                    String.valueOf(t.isEnabled()), String.valueOf(req.enabled()),
                    v -> t.setEnabled(req.enabled()));
        }
        if (req.highlighted() != null) {
            change(key, adminUsername, "highlighted",
                    String.valueOf(t.isHighlighted()), String.valueOf(req.highlighted()),
                    v -> t.setHighlighted(req.highlighted()));
        }
        if (req.displayOrder() != null) {
            change(key, adminUsername, "displayOrder",
                    String.valueOf(t.getDisplayOrder()), String.valueOf(req.displayOrder()),
                    v -> t.setDisplayOrder(req.displayOrder()));
        }
        // t is a managed entity; field changes flush on commit.
        return PricingMapper.toAdmin(t);
    }

    /** Applies the mutation and writes an audit row only when the value actually changes. */
    private void change(String key, String admin, String field, String oldValue, String newValue,
                        Consumer<Void> apply) {
        if (Objects.equals(oldValue, newValue)) {
            return;
        }
        apply.accept(null);
        audit.save(new ProductAuditEntry(key, admin, field, oldValue, newValue));
    }
}
