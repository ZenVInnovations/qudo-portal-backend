package com.pqc.product.pricing;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PricingTierRepository extends JpaRepository<PricingTier, Long> {

    /** Public listing: enabled tiers only, ordered for display. */
    List<PricingTier> findByEnabledTrueOrderByDisplayOrderAsc();

    /** Admin listing: every tier, ordered for display. */
    List<PricingTier> findAllByOrderByDisplayOrderAsc();
}
