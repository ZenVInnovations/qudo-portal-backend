package com.pqc.product.web;

import com.pqc.product.ProductService;
import com.pqc.product.dto.PublicProductDto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Public product catalog. Returns only products that are enabled AND public,
 * in display order — the backend is the source of truth for public visibility,
 * so a disabled or hidden product can never appear here. Served by the
 * permit-all public chain.
 */
@RestController
@RequestMapping("/api/v1/public/products")
public class PublicProductController {

    private final ProductService service;

    public PublicProductController(ProductService service) {
        this.service = service;
    }

    @GetMapping
    public List<PublicProductDto> list() {
        return service.getPublicProducts();
    }
}
