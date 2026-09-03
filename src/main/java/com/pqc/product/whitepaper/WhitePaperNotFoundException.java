package com.pqc.product.whitepaper;

/** Thrown when an admin mutation targets a white-paper id that does not exist. */
public class WhitePaperNotFoundException extends RuntimeException {

    public WhitePaperNotFoundException(Long id) {
        super("No white paper with id " + id);
    }
}
