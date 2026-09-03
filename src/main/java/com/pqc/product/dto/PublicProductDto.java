package com.pqc.product.dto;

/**
 * The public shape of a product — intentionally minimal. It deliberately omits
 * internal fields (id, enabled, visibility, audit, timestamps): the public API
 * never returns disabled or hidden products, so it never needs to expose those.
 */
public record PublicProductDto(
        String key,
        String name,
        String tagline,
        int displayOrder,
        String productType,
        String edition,
        String documentationUrl,
        String repositoryUrl
) {
}
