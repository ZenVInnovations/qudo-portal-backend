package com.pqc.product.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Admin session lifecycle. Login authenticates the single admin credential and
 * persists the security context into the HTTP session (so subsequent admin calls
 * carry it via the session cookie). {@code /me} lets the SPA discover whether it
 * is logged in — and, being a GET on the admin chain, it also seeds the
 * {@code XSRF-TOKEN} cookie the SPA needs to POST {@code /login}.
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AdminAuthController {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();

    public AdminAuthController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest body,
                                                     HttpServletRequest request,
                                                     HttpServletResponse response) {
        // Bad credentials throw BadCredentialsException → 401 via the advice.
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(body.username(), body.password()));

        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        return ResponseEntity.ok(Map.of("username", authentication.getName()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        securityContextHolderStrategy.clearContext();
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(Authentication authentication) {
        // Reached only when authenticated (the admin chain requires ROLE_ADMIN).
        return ResponseEntity.ok(Map.of("username", authentication.getName()));
    }

    public record LoginRequest(@NotBlank String username, @NotBlank String password) {
    }
}
