package com.pqc.product.pricing;

/** Thrown when an admin mutation targets a pricing-tier id that does not exist. */
public class PricingTierNotFoundException extends RuntimeException {

    public PricingTierNotFoundException(Long id) {
        super("No pricing tier with id " + id);
    }
}
