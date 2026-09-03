package com.pqc.product.pricing.web;

import com.pqc.product.pricing.PricingService;
import com.pqc.product.pricing.dto.PublicPricingTierDto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Public commercial pricing. Returns enabled tiers in display order, each with
 * its amount shown or withheld per the tier's visibility flag — the backend is
 * the source of truth for what pricing the public site shows. Served by the
 * permit-all public chain.
 */
@RestController
@RequestMapping("/api/v1/public/pricing")
public class PublicPricingController {

    private final PricingService service;

    public PublicPricingController(PricingService service) {
        this.service = service;
    }

    @GetMapping
    public List<PublicPricingTierDto> list() {
        return service.getPublicTiers();
    }
}
