package com.pqc.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Lookup + upsert for portal users authenticated via OAuth2.
 *
 * <p>One row per (provider, provider_subject) — i.e. one row per Google
 * account. On each successful login we either insert a new row or refresh
 * the existing row's display fields and bump last_login_at + login_count.</p>
 */
@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) { this.userRepository = userRepository; }

    /**
     * Insert-or-update the user record for the principal that just completed
     * an OAuth2 login. Call from the OAuth2 success handler.
     */
    @Transactional
    public User upsertFromOAuth(String provider, OAuth2User principal) {
        String subject = principal.getAttribute("sub");
        if (subject == null) subject = principal.getName();
        if (subject == null) {
            throw new IllegalArgumentException("OAuth2 principal has no subject / name");
        }

        String email = principal.getAttribute("email");
        String name = principal.getAttribute("name");
        String pictureUrl = principal.getAttribute("picture");
        Boolean emailVerified = principal.getAttribute("email_verified");

        final String sub = subject;
        return userRepository.findByProviderAndProviderSubject(provider, subject)
                .map(existing -> {
                    existing.recordLogin(email, name, pictureUrl, Boolean.TRUE.equals(emailVerified));
                    log.info("OAuth2 login: existing user {} ({}), loginCount={}",
                            existing.getId(), existing.getEmail(), existing.getLoginCount());
                    return existing;
                })
                .orElseGet(() -> {
                    User created = new User(UUID.randomUUID(), email, name, pictureUrl,
                            Boolean.TRUE.equals(emailVerified), provider, sub);
                    userRepository.save(created);
                    log.info("OAuth2 login: new user {} ({}, provider={})",
                            created.getId(), created.getEmail(), provider);
                    return created;
                });
    }

    @Transactional(readOnly = true)
    public User findByProviderSubject(String provider, String subject) {
        return userRepository.findByProviderAndProviderSubject(provider, subject).orElse(null);
    }
}
