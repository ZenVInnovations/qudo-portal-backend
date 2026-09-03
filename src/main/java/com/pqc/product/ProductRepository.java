package com.pqc.product;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ProductRepository extends JpaRepository<Product, Long> {

    /** Public listing: enabled AND the given visibility, ordered for display. */
    List<Product> findByEnabledTrueAndVisibilityOrderByDisplayOrderAsc(ProductVisibility visibility);

    /** Admin listing: every product, ordered for display. */
    List<Product> findAllByOrderByDisplayOrderAsc();
}
