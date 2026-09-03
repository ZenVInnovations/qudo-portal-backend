package com.pqc.product.whitepaper.dto;

import java.time.Instant;

/** The full white-paper shape returned to authenticated admins. */
public record AdminWhitePaperDto(
        Long id,
        String title,
        String description,
        String category,
        String documentUrl,
        boolean published,
        int displayOrder,
        Instant createdAt,
        Instant updatedAt
) {
}
