-- Collapse the catalog to three top-level products, each with a simple tagline:
--   QudoSSL       — Enterprise Quantum-Safe TLS   (Community/Commercial editions
--                   are chosen on the QudoSSL page, not as separate catalog rows)
--   QudoProvider  — Post-Quantum Provider for OpenSSL   (parked/disabled)
--   QudoPQC       — Post-Quantum Cryptography Library    (parked/disabled)
-- Idempotent: safe to re-run.

-- The two QudoSSL editions are no longer separate catalog products.
DELETE FROM products WHERE product_key IN ('qudossl-community', 'qudossl-commercial');

INSERT INTO products
    (product_key, name, tagline, description, enabled, display_order, visibility, product_type, edition, documentation_url, repository_url)
VALUES
    ('qudossl', 'QudoSSL', 'Enterprise Quantum-Safe TLS',
     'Quantum-safe TLS built on OpenSSL 3.5 LTS, offered in Community and Commercial editions.',
     TRUE, 1, 'PUBLIC', 'QUDOSSL_EDITION', NULL,
     '/get-started/qudossl', 'https://github.com/ZenVInnovations/qudossl')
ON CONFLICT (product_key) DO NOTHING;

UPDATE products
   SET name = 'QudoProvider',
       tagline = 'Post-Quantum Provider for OpenSSL',
       description = 'A drop-in OpenSSL provider that adds post-quantum algorithms to an existing OpenSSL installation. Parked; recoverable via the Admin Portal.',
       display_order = 2,
       documentation_url = '/get-started/qudoprovider'
 WHERE product_key = 'qudoprovider';

UPDATE products
   SET name = 'QudoPQC',
       tagline = 'Post-Quantum Cryptography Library',
       description = 'The post-quantum cryptography library — ML-KEM, ML-DSA and SLH-DSA primitives. Parked; recoverable via the Admin Portal.',
       display_order = 3,
       product_type = 'LIBRARY',
       documentation_url = '/docs'
 WHERE product_key = 'qudopqc';
