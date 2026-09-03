package com.pqc.product;

/** Coarse product category, used by the frontend to group/label products. */
public enum ProductType {
    /** A QudoSSL edition (Community or Commercial) — see {@link ProductEdition}. */
    QUDOSSL_EDITION,
    /** A standalone provider plugin (e.g. the parked Qudo Provider / Qudo PQC). */
    PROVIDER,
    /** A library. */
    LIBRARY
}
