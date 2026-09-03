package com.pqc.product.pricing.dto;

import java.time.Instant;

/** The full pricing-tier shape returned to authenticated admins. */
public record AdminPricingTierDto(
        Long id,
        String tierKey,
        String name,
        String audience,
        Long priceAmount,
        String currency,
        boolean priceVisible,
        boolean enabled,
        boolean highlighted,
        int displayOrder,
        Instant createdAt,
        Instant updatedAt
) {
}
