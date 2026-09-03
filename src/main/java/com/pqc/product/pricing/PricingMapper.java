package com.pqc.product.pricing;

import com.pqc.product.pricing.dto.AdminPricingTierDto;
import com.pqc.product.pricing.dto.PublicPricingTierDto;

/** Entity ↔ DTO mapping. Plain static methods (the repo uses no MapStruct/Lombok). */
public final class PricingMapper {

    private PricingMapper() {
    }

    public static PublicPricingTierDto toPublic(PricingTier t) {
        // Withhold the figure unless the tier is flagged to show it publicly.
        Long amount = t.isPriceVisible() ? t.getPriceAmount() : null;
        return new PublicPricingTierDto(
                t.getTierKey(),
                t.getName(),
                t.getAudience(),
                amount,
                t.getCurrency(),
                t.isHighlighted(),
                t.getDisplayOrder());
    }

    public static AdminPricingTierDto toAdmin(PricingTier t) {
        return new AdminPricingTierDto(
                t.getId(),
                t.getTierKey(),
                t.getName(),
                t.getAudience(),
                t.getPriceAmount(),
                t.getCurrency(),
                t.isPriceVisible(),
                t.isEnabled(),
                t.isHighlighted(),
                t.getDisplayOrder(),
                t.getCreatedAt(),
                t.getUpdatedAt());
    }
}
