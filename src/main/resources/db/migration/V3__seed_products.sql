-- Initial product catalog. Idempotent: ON CONFLICT DO NOTHING keeps this safe to
-- re-run and means an operator's later enable/disable changes are never clobbered
-- by a redeploy. Product keys are stable identifiers.
--
-- Launch state:
--   qudossl-community   ON   (public)
--   qudossl-commercial  ON   (public)
--   qudoprovider        OFF  (parked — recoverable via the Admin Portal)
--   qudopqc             OFF  (parked — recoverable via the Admin Portal)
--
-- Copy is intentionally conservative and guardrail-safe: "runs in FIPS mode",
-- never "FIPS validated/certified". No CMVP/CAVP claims. ML-KEM/ML-DSA are NIST
-- standards, not ZENV inventions.
INSERT INTO products
    (product_key, name, tagline, description, enabled, display_order, visibility, product_type, edition, documentation_url, repository_url)
VALUES
    ('qudossl-community', 'QudoSSL Community Edition',
     'Free, open-source post-quantum TLS built on OpenSSL 3.5.7.',
     'An OpenSSL 3.5.7 LTS distribution that delegates its ML-KEM (FIPS 203) and ML-DSA (FIPS 204) mathematics to ZENV''s qudo-pqc-lib, with a Standard build and a FIPS-mode build. Apache-2.0. Not a FIPS-validated module; validation in preparation.',
     TRUE, 1, 'PUBLIC', 'QUDOSSL_EDITION', 'COMMUNITY',
     '/products/qudossl-community', 'https://github.com/ZenVInnovations/qudossl'),

    ('qudossl-commercial', 'QudoSSL Commercial Edition',
     'Supported, reproducible build of unmodified upstream OpenSSL 3.5.7 LTS.',
     'A reproducible, ZENV-supported build of unmodified upstream OpenSSL 3.5.7 LTS — no modified cryptography. Post-quantum capable today via upstream''s own ML-KEM/ML-DSA; runs in FIPS mode using the OpenSSL FIPS provider. Not a validated module.',
     TRUE, 2, 'PUBLIC', 'QUDOSSL_EDITION', 'COMMERCIAL',
     '/products/qudossl-commercial', NULL),

    ('qudoprovider', 'Qudo Provider',
     'Post-quantum provider plugin for an existing OpenSSL install.',
     'Parked. A standalone Qudo PQC provider that loads into an existing OpenSSL''s ossl-modules directory. Preserved for potential future reactivation.',
     FALSE, 3, 'PUBLIC', 'PROVIDER', NULL, NULL, NULL),

    ('qudopqc', 'Qudo PQC',
     'ZENV post-quantum cryptography.',
     'Parked. Preserved for potential future reactivation.',
     FALSE, 4, 'PUBLIC', 'PROVIDER', NULL, NULL, NULL)
ON CONFLICT (product_key) DO NOTHING;
