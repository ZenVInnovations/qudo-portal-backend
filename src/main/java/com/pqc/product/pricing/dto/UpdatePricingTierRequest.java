package com.pqc.product.pricing.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Partial update of a pricing tier. Every field is optional — only non-null
 * fields are applied — so the admin UI can send just {@code {"priceAmount":
 * 30000}} to change a price, or flip {@code priceVisible} to switch a tier
 * between a public figure and "Contact sales". The stable {@code tierKey} is not
 * editable.
 */
public record UpdatePricingTierRequest(
        @Size(max = 128, message = "name too long")
        String name,

        @Size(max = 512, message = "audience too long")
        String audience,

        @Min(value = 0, message = "priceAmount must be >= 0")
        Long priceAmount,

        @Pattern(regexp = "[A-Z]{3}", message = "currency must be a 3-letter ISO code")
        String currency,

        Boolean priceVisible,

        Boolean enabled,

        Boolean highlighted,

        @Min(value = 0, message = "displayOrder must be >= 0")
        Integer displayOrder
) {
}
