package com.pqc.product;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ProductAuditRepository extends JpaRepository<ProductAuditEntry, Long> {

    /** Recent audit entries for one product, newest first. */
    List<ProductAuditEntry> findTop50ByProductKeyOrderByChangedAtDesc(String productKey);
}
