package com.pqc.product.whitepaper;

import com.pqc.product.whitepaper.dto.AdminWhitePaperDto;
import com.pqc.product.whitepaper.dto.PublicWhitePaperDto;

/** Entity ↔ DTO mapping. Plain static methods (the repo uses no MapStruct/Lombok). */
public final class WhitePaperMapper {

    private WhitePaperMapper() {
    }

    public static PublicWhitePaperDto toPublic(WhitePaper w) {
        return new PublicWhitePaperDto(
                w.getId(),
                w.getTitle(),
                w.getDescription(),
                w.getCategory(),
                w.getDocumentUrl(),
                w.getDisplayOrder());
    }

    public static AdminWhitePaperDto toAdmin(WhitePaper w) {
        return new AdminWhitePaperDto(
                w.getId(),
                w.getTitle(),
                w.getDescription(),
                w.getCategory(),
                w.getDocumentUrl(),
                w.isPublished(),
                w.getDisplayOrder(),
                w.getCreatedAt(),
                w.getUpdatedAt());
    }
}
