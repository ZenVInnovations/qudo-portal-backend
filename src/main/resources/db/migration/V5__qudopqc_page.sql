-- QudoPQC now has its own product page (the SDK / "PQC for your code" content,
-- split out from the QudoProvider walkthrough). Point its documentation link at
-- that page instead of the general docs. Idempotent.
UPDATE products SET documentation_url = '/get-started/qudopqc' WHERE product_key = 'qudopqc';
