package com.pqc.product.whitepaper;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface WhitePaperRepository extends JpaRepository<WhitePaper, Long> {

    /** Public listing: published only, ordered for display. */
    List<WhitePaper> findByPublishedTrueOrderByDisplayOrderAsc();

    /** Admin listing: all, ordered for display. */
    List<WhitePaper> findAllByOrderByDisplayOrderAsc();
}
