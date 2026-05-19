package com.pqc.config;

import com.pqc.user.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Security wiring with one switch: {@code app.auth.enabled}.
 *
 * <ul>
 *   <li><b>false (default)</b> — Spring Security is on the classpath but the
 *   filter chain permits every route. Matches the public-portal mode that
 *   exists today. CSRF is disabled in this mode because there are no
 *   authenticated sessions to protect.</li>
 *
 *   <li><b>true</b> — full OAuth2 login chain with Google as the IdP. On
 *   successful auth we upsert the user into Postgres via
 *   {@link UserService#upsertFromOAuth(String, OAuth2User)} before
 *   redirecting back to the SPA.</li>
 * </ul>
 *
 * <p>Set {@code APP_AUTH_ENABLED=true} alongside {@code GOOGLE_CLIENT_ID} and
 * {@code GOOGLE_CLIENT_SECRET} to flip from public to authenticated mode.</p>
 */
@Configuration
public class SecurityConfig {

    @Value("${app.auth.enabled:false}")
    private boolean authEnabled;

    @Value("${app.frontend.origin:http://localhost:5173}")
    private String frontendOrigin;

    private final UserService userService;

    public SecurityConfig(UserService userService) { this.userService = userService; }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        if (!authEnabled) {
            // Public-portal mode. Everything is permitted; CSRF off because
            // no authenticated sessions exist. CORS still respects the
            // configured frontend origin.
            return http
                    .cors(Customizer.withDefaults())
                    .csrf(csrf -> csrf.disable())
                    .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .build();
        }

        // Authenticated-portal mode: Google OAuth2 + DB upsert on login.
        var csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        var csrfHandler = new CsrfTokenRequestAttributeHandler();
        csrfHandler.setCsrfRequestAttributeName(null);

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository)
                        .csrfTokenRequestHandler(csrfHandler)
                        .ignoringRequestMatchers("/api/v1/public/**"))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/", "/actuator/health", "/actuator/info").permitAll()
                        .requestMatchers("/api/v1/public/**").permitAll()
                        .requestMatchers("/api/v1/me").permitAll()
                        .requestMatchers("/oauth2/**", "/login/**").permitAll()
                        .requestMatchers("/api/v1/sandbox/**").authenticated()
                        .requestMatchers("/api/v1/downloads/**").authenticated()
                        .anyRequest().permitAll())
                .oauth2Login(o -> o
                        .successHandler(oauth2SuccessHandler())
                        .failureUrl(frontendOrigin + "/login?error=oauth"))
                .logout(l -> l
                        .logoutUrl("/api/v1/logout")
                        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req, res, ex) -> res.sendError(401, "Unauthorized")));

        return http.build();
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

    private AuthenticationSuccessHandler oauth2SuccessHandler() {
        var handler = new SimpleUrlAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl(frontendOrigin + "/");
        handler.setAlwaysUseDefaultTargetUrl(false);

        // Wrap the redirect handler so we can upsert the user before the
        // redirect fires. Google is the only provider wired today.
        return (request, response, authentication) -> {
            if (authentication.getPrincipal() instanceof OAuth2User principal) {
                userService.upsertFromOAuth("google", principal);
            }
            handler.onAuthenticationSuccess(request, response, authentication);
        };
    }
}
