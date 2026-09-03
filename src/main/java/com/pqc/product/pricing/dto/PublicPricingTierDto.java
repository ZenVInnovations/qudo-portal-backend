package com.pqc.product.pricing.dto;

/**
 * A pricing tier as shown on the public site. {@code amount} is null when the
 * tier's price is withheld ({@code priceVisible = false}) — the frontend then
 * renders "Contact sales" instead of a figure. Internal flags (enabled,
 * priceVisible, timestamps) are never exposed here.
 */
public record PublicPricingTierDto(
        String tierKey,
        String name,
        String audience,
        Long amount,
        String currency,
        boolean highlighted,
        int displayOrder
) {
}
