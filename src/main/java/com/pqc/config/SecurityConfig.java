package com.pqc.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Two security filter chains:
 *
 * <ol>
 *   <li><b>adminChain</b> ({@code /api/v1/admin/**}) — the first real
 *       authentication in this service. Requires a {@code ROLE_ADMIN} session,
 *       backed by a single credential from env. CSRF is enabled with a
 *       JS-readable cookie ({@code XSRF-TOKEN}) so the SPA's existing
 *       cookie→header handling protects the state-changing calls.</li>
 *   <li><b>publicChain</b> (everything else) — unchanged from before: CORS +
 *       stateless + permit-all. The sandbox/demo/scanner surface stays free to
 *       evaluate, defended by the per-IP {@link RateLimitFilter}.</li>
 * </ol>
 *
 * <p>The former Google/OAuth2 chain that once lived here was removed long ago;
 * this is a fresh, purpose-built admin chain, not a revival of that config.</p>
 */
@Configuration
@EnableConfigurationProperties(AdminAuthProperties.class)
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${app.frontend.origin:http://localhost:5173}")
    private String frontendOrigin;

    @Bean
    @Order(1)
    public SecurityFilterChain adminSecurityChain(HttpSecurity http) throws Exception {
        // Plain handler (not the XOR default): the cookie value equals the header
        // value, which is what the SPA client echoes back.
        var csrfHandler = new CsrfTokenRequestAttributeHandler();
        http
                .securityMatcher("/api/v1/admin/**")
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfHandler))
                .addFilterAfter(new CsrfCookieFilter(), CsrfFilter.class)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        // Login itself is unauthenticated (but still CSRF-protected —
                        // the SPA fetches the token via a prior GET). Everything else
                        // under /admin requires an authenticated admin.
                        .requestMatchers(HttpMethod.POST, "/api/v1/admin/login").permitAll()
                        .anyRequest().hasRole("ADMIN"))
                .exceptionHandling(e -> e.authenticationEntryPoint(jsonAuthEntryPoint()));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain publicSecurityChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/**")
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        var cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of(frontendOrigin));
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("*"));
        cfg.setExposedHeaders(List.of("X-XSRF-TOKEN"));
        cfg.setAllowCredentials(true);
        cfg.setMaxAge(3600L);

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
    }

    /**
     * The single admin account. Fails closed if credentials are not configured —
     * the app will not start, which is the safe outcome: better a hard failure at
     * boot than an admin API guarded by a blank or default password. The
     * {@code local} profile supplies a clearly-flagged dev-only default.
     */
    @Bean
    public UserDetailsService adminUserDetailsService(AdminAuthProperties props) {
        if (!StringUtils.hasText(props.getUsername()) || !StringUtils.hasText(props.getPasswordHash())) {
            throw new IllegalStateException(
                    "Admin credentials are not configured. Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH "
                    + "(a BCrypt hash) — the product-management admin API refuses to start without them. "
                    + "The 'local' profile ships a dev-only default.");
        }
        UserDetails admin = User.withUsername(props.getUsername())
                .password(props.getPasswordHash())
                .roles("ADMIN")
                .build();
        log.info("Product-management admin API enabled for user '{}'.", props.getUsername());
        return new InMemoryUserDetailsManager(admin);
    }

    private AuthenticationEntryPoint jsonAuthEntryPoint() {
        return (request, response, ex) -> {
            response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"status\":\"error\",\"message\":\"authentication required\"}");
        };
    }
}
