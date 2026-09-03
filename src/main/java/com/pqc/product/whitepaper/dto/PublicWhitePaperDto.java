package com.pqc.product.whitepaper.dto;

/** A white paper as shown on the public Resources page (published rows only). */
public record PublicWhitePaperDto(
        Long id,
        String title,
        String description,
        String category,
        String documentUrl,
        int displayOrder
) {
}
