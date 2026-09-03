package com.pqc.product.whitepaper.web;

import com.pqc.product.whitepaper.WhitePaperService;
import com.pqc.product.whitepaper.dto.PublicWhitePaperDto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Public white papers. Returns published rows in display order — the backend is
 * the source of truth for what's shown on the Resources page. Served by the
 * permit-all public chain.
 */
@RestController
@RequestMapping("/api/v1/public/whitepapers")
public class PublicWhitePaperController {

    private final WhitePaperService service;

    public PublicWhitePaperController(WhitePaperService service) {
        this.service = service;
    }

    @GetMapping
    public List<PublicWhitePaperDto> list() {
        return service.getPublished();
    }
}
