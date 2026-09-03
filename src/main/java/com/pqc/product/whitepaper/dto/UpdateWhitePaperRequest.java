package com.pqc.product.whitepaper.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Partial update of a white paper — only non-null fields are applied. */
public record UpdateWhitePaperRequest(
        @Size(max = 256, message = "title too long")
        String title,

        @Size(max = 4000, message = "description too long")
        String description,

        @Size(max = 64, message = "category too long")
        String category,

        @Size(max = 1024, message = "documentUrl too long")
        @Pattern(regexp = "(https?://.+|/.+)", message = "documentUrl must be an http(s) URL or a site path starting with /")
        String documentUrl,

        Boolean published,

        @Min(value = 0, message = "displayOrder must be >= 0")
        Integer displayOrder
) {
}
