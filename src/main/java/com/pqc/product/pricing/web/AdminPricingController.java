package com.pqc.product.pricing.web;

import com.pqc.product.pricing.PricingService;
import com.pqc.product.pricing.dto.AdminPricingTierDto;
import com.pqc.product.pricing.dto.UpdatePricingTierRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin pricing management. Behind the authenticated admin filter chain
 * ({@code ROLE_ADMIN} + CSRF), same as product management. List and update the
 * proposed commercial tiers — edit a price, switch a tier between a public figure
 * and "Contact sales", or reorder.
 */
@RestController
@RequestMapping("/api/v1/admin/pricing")
public class AdminPricingController {

    private final PricingService service;

    public AdminPricingController(PricingService service) {
        this.service = service;
    }

    @GetMapping
    public List<AdminPricingTierDto> list() {
        return service.getAllTiers();
    }

    @PutMapping("/{id}")
    public AdminPricingTierDto update(@PathVariable Long id,
                                      @Valid @RequestBody UpdatePricingTierRequest request,
                                      Authentication authentication) {
        return service.updateTier(id, request, authentication.getName());
    }
}
