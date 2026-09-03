-- Present the support tiers top-down — Enterprise first, Basic last — and
-- feature Enterprise instead of Engineering. Idempotent UPDATEs, keyed by the
-- immutable tier_key.
UPDATE pricing_tiers SET display_order = 1 WHERE tier_key = 'enterprise';
UPDATE pricing_tiers SET display_order = 2 WHERE tier_key = 'engineering';
UPDATE pricing_tiers SET display_order = 3 WHERE tier_key = 'basic';

UPDATE pricing_tiers SET highlighted = FALSE WHERE tier_key = 'engineering';
UPDATE pricing_tiers SET highlighted = TRUE  WHERE tier_key = 'enterprise';
