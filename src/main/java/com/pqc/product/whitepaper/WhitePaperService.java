package com.pqc.product.whitepaper;

import com.pqc.product.ProductAuditEntry;
import com.pqc.product.ProductAuditRepository;
import com.pqc.product.whitepaper.dto.AdminWhitePaperDto;
import com.pqc.product.whitepaper.dto.CreateWhitePaperRequest;
import com.pqc.product.whitepaper.dto.PublicWhitePaperDto;
import com.pqc.product.whitepaper.dto.UpdateWhitePaperRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * White-paper operations. Public reads return only published rows. Admin writes
 * (create / update / delete) are recorded in the shared {@code product_audit}
 * trail under a {@code whitepaper:<id>} key namespace.
 */
@Service
public class WhitePaperService {

    private static final String AUDIT_KEY_PREFIX = "whitepaper:";

    private final WhitePaperRepository papers;
    private final ProductAuditRepository audit;

    public WhitePaperService(WhitePaperRepository papers, ProductAuditRepository audit) {
        this.papers = papers;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<PublicWhitePaperDto> getPublished() {
        return papers.findByPublishedTrueOrderByDisplayOrderAsc()
                .stream().map(WhitePaperMapper::toPublic).toList();
    }

    @Transactional(readOnly = true)
    public List<AdminWhitePaperDto> getAll() {
        return papers.findAllByOrderByDisplayOrderAsc()
                .stream().map(WhitePaperMapper::toAdmin).toList();
    }

    @Transactional
    public AdminWhitePaperDto create(CreateWhitePaperRequest req, String adminUsername) {
        WhitePaper w = new WhitePaper();
        w.setTitle(req.title());
        w.setDescription(req.description());
        w.setCategory(req.category());
        w.setDocumentUrl(req.documentUrl());
        w.setPublished(req.published() == null || req.published());
        w.setDisplayOrder(req.displayOrder() == null ? 0 : req.displayOrder());
        WhitePaper saved = papers.save(w);
        audit.save(new ProductAuditEntry(
                AUDIT_KEY_PREFIX + saved.getId(), adminUsername, "created", null, saved.getTitle()));
        return WhitePaperMapper.toAdmin(saved);
    }

    @Transactional
    public AdminWhitePaperDto update(Long id, UpdateWhitePaperRequest req, String adminUsername) {
        WhitePaper w = papers.findById(id).orElseThrow(() -> new WhitePaperNotFoundException(id));
        String key = AUDIT_KEY_PREFIX + id;

        if (req.title() != null) {
            change(key, adminUsername, "title", w.getTitle(), req.title(), v -> w.setTitle(req.title()));
        }
        if (req.description() != null) {
            change(key, adminUsername, "description", w.getDescription(), req.description(), v -> w.setDescription(req.description()));
        }
        if (req.category() != null) {
            change(key, adminUsername, "category", w.getCategory(), req.category(), v -> w.setCategory(req.category()));
        }
        if (req.documentUrl() != null) {
            change(key, adminUsername, "documentUrl", w.getDocumentUrl(), req.documentUrl(), v -> w.setDocumentUrl(req.documentUrl()));
        }
        if (req.published() != null) {
            change(key, adminUsername, "published",
                    String.valueOf(w.isPublished()), String.valueOf(req.published()),
                    v -> w.setPublished(req.published()));
        }
        if (req.displayOrder() != null) {
            change(key, adminUsername, "displayOrder",
                    String.valueOf(w.getDisplayOrder()), String.valueOf(req.displayOrder()),
                    v -> w.setDisplayOrder(req.displayOrder()));
        }
        return WhitePaperMapper.toAdmin(w);
    }

    @Transactional
    public void delete(Long id, String adminUsername) {
        WhitePaper w = papers.findById(id).orElseThrow(() -> new WhitePaperNotFoundException(id));
        audit.save(new ProductAuditEntry(
                AUDIT_KEY_PREFIX + id, adminUsername, "deleted", w.getTitle(), null));
        papers.delete(w);
    }

    private void change(String key, String admin, String field, String oldValue, String newValue,
                        Consumer<Void> apply) {
        if (Objects.equals(oldValue, newValue)) {
            return;
        }
        apply.accept(null);
        audit.save(new ProductAuditEntry(key, admin, field, oldValue, newValue));
    }
}
