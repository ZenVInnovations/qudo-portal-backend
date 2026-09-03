package com.pqc.product.whitepaper.web;

import com.pqc.product.whitepaper.WhitePaperService;
import com.pqc.product.whitepaper.dto.AdminWhitePaperDto;
import com.pqc.product.whitepaper.dto.CreateWhitePaperRequest;
import com.pqc.product.whitepaper.dto.UpdateWhitePaperRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin white-paper management. Behind the authenticated admin filter chain
 * ({@code ROLE_ADMIN} + CSRF). Submit, edit, publish/unpublish, reorder, and
 * remove white papers shown on the public Resources page.
 */
@RestController
@RequestMapping("/api/v1/admin/whitepapers")
public class AdminWhitePaperController {

    private final WhitePaperService service;

    public AdminWhitePaperController(WhitePaperService service) {
        this.service = service;
    }

    @GetMapping
    public List<AdminWhitePaperDto> list() {
        return service.getAll();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public AdminWhitePaperDto create(@Valid @RequestBody CreateWhitePaperRequest request,
                                     Authentication authentication) {
        return service.create(request, authentication.getName());
    }

    @PutMapping("/{id}")
    public AdminWhitePaperDto update(@PathVariable Long id,
                                     @Valid @RequestBody UpdateWhitePaperRequest request,
                                     Authentication authentication) {
        return service.update(id, request, authentication.getName());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id, Authentication authentication) {
        service.delete(id, authentication.getName());
    }
}
