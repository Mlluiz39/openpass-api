-- TOTP (2FA) support.
--
-- The shared secret must never sit in plaintext next to the entry, so it lives
-- in its own column encrypted with the same app key as the stored value. The
-- metadata/tags columns stay readable by design (search, matching by URL),
-- which is exactly why the secret does not go there.
ALTER TABLE entries ADD COLUMN IF NOT EXISTS encrypted_totp TEXT;
