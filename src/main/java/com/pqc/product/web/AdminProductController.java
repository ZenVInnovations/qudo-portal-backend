package com.pqc.product.web;

import com.pqc.product.ProductService;
import com.pqc.product.dto.AdminProductDto;
import com.pqc.product.dto.ProductAuditDto;
import com.pqc.product.dto.UpdateProductRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin product management. Every route here is behind the authenticated admin
 * filter chain (ROLE_ADMIN + CSRF). Kept intentionally small — list, update,
 * and read the audit trail — per the "control availability, not a full CMS"
 * scope.
 */
@RestController
@RequestMapping("/api/v1/admin/products")
public class AdminProductController {

    private final ProductService service;

    public AdminProductController(ProductService service) {
        this.service = service;
    }

    @GetMapping
    public List<AdminProductDto> list() {
        return service.getAllProducts();
    }

    @PutMapping("/{id}")
    public AdminProductDto update(@PathVariable Long id,
                                  @Valid @RequestBody UpdateProductRequest request,
                                  Authentication authentication) {
        return service.updateProduct(id, request, authentication.getName());
    }

    @GetMapping("/{id}/audit")
    public List<ProductAuditDto> audit(@PathVariable Long id) {
        return service.getAudit(id);
    }
}
