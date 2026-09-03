package com.pqc.product;

import com.pqc.product.dto.AdminProductDto;
import com.pqc.product.dto.ProductAuditDto;
import com.pqc.product.dto.PublicProductDto;
import com.pqc.product.dto.UpdateProductRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Product-catalog operations. Public reads are filtered at the query level
 * (enabled + PUBLIC only), so a disabled product can never leak through the
 * public path. Admin updates are applied field-by-field, writing one audit row
 * per actually-changed field.
 */
@Service
public class ProductService {

    private final ProductRepository products;
    private final ProductAuditRepository audit;

    public ProductService(ProductRepository products, ProductAuditRepository audit) {
        this.products = products;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<PublicProductDto> getPublicProducts() {
        return products.findByEnabledTrueAndVisibilityOrderByDisplayOrderAsc(ProductVisibility.PUBLIC)
                .stream().map(ProductMapper::toPublic).toList();
    }

    @Transactional(readOnly = true)
    public List<AdminProductDto> getAllProducts() {
        return products.findAllByOrderByDisplayOrderAsc()
                .stream().map(ProductMapper::toAdmin).toList();
    }

    @Transactional(readOnly = true)
    public List<ProductAuditDto> getAudit(Long id) {
        Product product = products.findById(id).orElseThrow(() -> new ProductNotFoundException(id));
        return audit.findTop50ByProductKeyOrderByChangedAtDesc(product.getProductKey())
                .stream().map(ProductMapper::toAuditDto).toList();
    }

    @Transactional
    public AdminProductDto updateProduct(Long id, UpdateProductRequest req, String adminUsername) {
        Product p = products.findById(id).orElseThrow(() -> new ProductNotFoundException(id));
        String key = p.getProductKey();

        if (req.enabled() != null) {
            change(key, adminUsername, "enabled",
                    String.valueOf(p.isEnabled()), String.valueOf(req.enabled()),
                    v -> p.setEnabled(req.enabled()));
        }
        if (req.displayOrder() != null) {
            change(key, adminUsername, "displayOrder",
                    String.valueOf(p.getDisplayOrder()), String.valueOf(req.displayOrder()),
                    v -> p.setDisplayOrder(req.displayOrder()));
        }
        if (req.visibility() != null) {
            ProductVisibility target = ProductVisibility.valueOf(req.visibility());
            change(key, adminUsername, "visibility",
                    p.getVisibility().name(), target.name(),
                    v -> p.setVisibility(target));
        }
        if (req.name() != null) {
            change(key, adminUsername, "name", p.getName(), req.name(), v -> p.setName(req.name()));
        }
        if (req.tagline() != null) {
            change(key, adminUsername, "tagline", p.getTagline(), req.tagline(), v -> p.setTagline(req.tagline()));
        }
        if (req.description() != null) {
            change(key, adminUsername, "description", p.getDescription(), req.description(), v -> p.setDescription(req.description()));
        }
        if (req.documentationUrl() != null) {
            change(key, adminUsername, "documentationUrl", p.getDocumentationUrl(), req.documentationUrl(), v -> p.setDocumentationUrl(req.documentationUrl()));
        }
        if (req.repositoryUrl() != null) {
            change(key, adminUsername, "repositoryUrl", p.getRepositoryUrl(), req.repositoryUrl(), v -> p.setRepositoryUrl(req.repositoryUrl()));
        }
        // p is a managed entity; field changes flush on commit.
        return ProductMapper.toAdmin(p);
    }

    /** Applies the mutation and writes an audit row only when the value actually changes. */
    private void change(String key, String admin, String field, String oldValue, String newValue,
                        Consumer<Void> apply) {
        if (Objects.equals(oldValue, newValue)) {
            return;
        }
        apply.accept(null);
        audit.save(new ProductAuditEntry(key, admin, field, oldValue, newValue));
    }
}
