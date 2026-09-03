package com.pqc.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Renders the CSRF token on every request so the {@code XSRF-TOKEN} cookie is
 * actually written. {@link org.springframework.security.web.csrf.CookieCsrfTokenRepository}
 * defers the cookie until the token is read; the SPA never reads it server-side,
 * so without this the cookie would only appear after an unsafe request. The
 * frontend ({@code src/api/client.ts}) reads that cookie and echoes it back as
 * the {@code X-XSRF-TOKEN} header.
 */
public final class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            // Reading the token value triggers the deferred cookie write.
            csrfToken.getToken();
        }
        filterChain.doFilter(request, response);
    }
}
