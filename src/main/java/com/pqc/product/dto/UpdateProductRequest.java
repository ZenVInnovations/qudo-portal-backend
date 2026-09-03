package com.pqc.product.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Partial update of a product. Every field is optional — only the non-null
 * fields are applied — so the admin UI can send just {@code {"enabled": false}}
 * to toggle a product, or reorder / edit metadata as needed. The stable
 * {@code productKey} and {@code productType} are intentionally not editable.
 */
public record UpdateProductRequest(
        Boolean enabled,

        @Min(value = 0, message = "displayOrder must be >= 0")
        Integer displayOrder,

        @Pattern(regexp = "PUBLIC|HIDDEN", message = "visibility must be PUBLIC or HIDDEN")
        String visibility,

        @Size(max = 128, message = "name too long")
        String name,

        @Size(max = 256, message = "tagline too long")
        String tagline,

        String description,

        @Size(max = 512, message = "documentationUrl too long")
        String documentationUrl,

        @Size(max = 512, message = "repositoryUrl too long")
        String repositoryUrl
) {
}
