package com.pqc.product.web;

import com.pqc.product.ProductNotFoundException;
import com.pqc.product.pricing.PricingTierNotFoundException;
import com.pqc.product.whitepaper.WhitePaperNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * Error handling for the product/admin API only ({@code basePackages} scopes it
 * to {@code com.pqc.product}), so the existing controllers keep their own inline
 * error shaping. Responses use the same {@code {status, message}} shape the rest
 * of the service uses.
 */
@RestControllerAdvice(basePackages = "com.pqc.product")
public class ProductApiExceptionHandler {

    @ExceptionHandler(ProductNotFoundException.class)
    public ResponseEntity<Map<String, Object>> notFound(ProductNotFoundException ex) {
        return error(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(PricingTierNotFoundException.class)
    public ResponseEntity<Map<String, Object>> pricingTierNotFound(PricingTierNotFoundException ex) {
        return error(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(WhitePaperNotFoundException.class)
    public ResponseEntity<Map<String, Object>> whitePaperNotFound(WhitePaperNotFoundException ex) {
        return error(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> invalid(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .collect(Collectors.joining("; "));
        return error(HttpStatus.BAD_REQUEST, message.isBlank() ? "validation failed" : message);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> unreadable(HttpMessageNotReadableException ex) {
        return error(HttpStatus.BAD_REQUEST, "malformed request body");
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> badCredentials(BadCredentialsException ex) {
        return error(HttpStatus.UNAUTHORIZED, "invalid username or password");
    }

    private ResponseEntity<Map<String, Object>> error(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(Map.of("status", "error", "message", message));
    }
}
