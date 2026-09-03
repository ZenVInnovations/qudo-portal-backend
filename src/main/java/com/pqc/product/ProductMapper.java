package com.pqc.product;

import com.pqc.product.dto.AdminProductDto;
import com.pqc.product.dto.ProductAuditDto;
import com.pqc.product.dto.PublicProductDto;

/** Entity ↔ DTO mapping. Plain static methods (the repo uses no MapStruct/Lombok). */
public final class ProductMapper {

    private ProductMapper() {
    }

    public static PublicProductDto toPublic(Product p) {
        return new PublicProductDto(
                p.getProductKey(),
                p.getName(),
                p.getTagline(),
                p.getDisplayOrder(),
                name(p.getProductType()),
                name(p.getEdition()),
                p.getDocumentationUrl(),
                p.getRepositoryUrl());
    }

    public static AdminProductDto toAdmin(Product p) {
        return new AdminProductDto(
                p.getId(),
                p.getProductKey(),
                p.getName(),
                p.getTagline(),
                p.getDescription(),
                p.isEnabled(),
                p.getDisplayOrder(),
                name(p.getVisibility()),
                name(p.getProductType()),
                name(p.getEdition()),
                p.getDocumentationUrl(),
                p.getRepositoryUrl(),
                p.getCreatedAt(),
                p.getUpdatedAt());
    }

    public static ProductAuditDto toAuditDto(ProductAuditEntry a) {
        return new ProductAuditDto(
                a.getProductKey(),
                a.getAdminUsername(),
                a.getFieldChanged(),
                a.getOldValue(),
                a.getNewValue(),
                a.getChangedAt());
    }

    private static String name(Enum<?> e) {
        return e == null ? null : e.name();
    }
}
