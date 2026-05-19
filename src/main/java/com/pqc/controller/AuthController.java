package com.pqc.controller;

import com.pqc.user.User;
import com.pqc.user.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Current-user endpoint. Behaviour depends on {@code app.auth.enabled}:
 * <ul>
 *   <li>Auth disabled — always returns {@code {authenticated: false}}.</li>
 *   <li>Auth enabled, signed in — returns the persisted {@link User} row
 *       (DB-backed identity + login history), not just the OAuth2 claims.</li>
 *   <li>Auth enabled, anonymous — returns {@code {authenticated: false}}
 *       (Spring Security permits this route).</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) { this.userService = userService; }

    @GetMapping("/me")
    public ResponseEntity<?> me(@AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.ok(Map.of("authenticated", false));
        }

        String subject = principal.getAttribute("sub");
        if (subject == null) subject = principal.getName();

        User user = userService.findByProviderSubject("google", subject);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("authenticated", true);
        if (user != null) {
            // Prefer the persisted row — it carries server-stamped fields
            // (createdAt, loginCount) the OAuth2 principal doesn't have.
            body.put("id", user.getId().toString());
            body.put("email", user.getEmail());
            body.put("name", user.getName());
            body.put("picture", user.getPictureUrl());
            body.put("emailVerified", user.isEmailVerified());
            body.put("createdAt", user.getCreatedAt().toString());
            body.put("lastLoginAt", user.getLastLoginAt().toString());
            body.put("loginCount", user.getLoginCount());
        } else {
            // Fallback to OAuth2 claims if the upsert hasn't run yet.
            body.put("email", principal.<String>getAttribute("email"));
            body.put("name", principal.<String>getAttribute("name"));
            body.put("picture", principal.<String>getAttribute("picture"));
            body.put("emailVerified", principal.<Boolean>getAttribute("email_verified"));
        }
        return ResponseEntity.ok(body);
    }
}
