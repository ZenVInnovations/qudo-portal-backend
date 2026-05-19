package com.pqc.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Auth stub. Returns "not authenticated" until Google OAuth2 is wired in.
 * The frontend reads this to decide whether to show the sign-in CTA.
 *
 * When auth is added back:
 * - Re-add spring-boot-starter-security + spring-boot-starter-oauth2-client to pom.xml
 * - Restore SecurityConfig.java (kept in git history at commit b4828e6's parent)
 * - Inject @AuthenticationPrincipal OAuth2User and return its claims
 */
@RestController
@RequestMapping("/api/v1")
public class AuthController {

    @GetMapping("/me")
    public ResponseEntity<?> me() {
        return ResponseEntity.ok(Map.of("authenticated", false));
    }
}
