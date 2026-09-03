package com.pqc.product.dto;

import java.time.Instant;

/** One audit record, as returned by the admin audit endpoint. */
public record ProductAuditDto(
        String productKey,
        String adminUsername,
        String fieldChanged,
        String oldValue,
        String newValue,
        Instant changedAt
) {
}
