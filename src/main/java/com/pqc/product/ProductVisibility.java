package com.pqc.product;

/**
 * Whether a product is eligible to appear on the public portal. This is separate
 * from {@code enabled}: a product must be BOTH {@code enabled} AND
 * {@link #PUBLIC} to be returned by the public API. {@link #HIDDEN} keeps a
 * product out of the public API regardless of its enabled flag.
 */
public enum ProductVisibility {
    PUBLIC,
    HIDDEN
}
