package com.pqc.product.dto;

import java.time.Instant;

/** The full product shape returned to authenticated admins. */
public record AdminProductDto(
        Long id,
        String key,
        String name,
        String tagline,
        String description,
        boolean enabled,
        int displayOrder,
        String visibility,
        String productType,
        String edition,
        String documentationUrl,
        String repositoryUrl,
        Instant createdAt,
        Instant updatedAt
) {
}
