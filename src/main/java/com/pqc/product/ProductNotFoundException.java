package com.pqc.product;

/** Thrown when an admin mutation targets a product id that does not exist. */
public class ProductNotFoundException extends RuntimeException {

    public ProductNotFoundException(Long id) {
        super("No product with id " + id);
    }
}
