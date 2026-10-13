-- Usage notes for Agents on a connection (non-secret headers to send, where ids come from); never a secret.
ALTER TABLE connections ADD COLUMN description TEXT NOT NULL DEFAULT '';
-- Temporary scope extensions of a connection grant: a JSON array of {paths?, methods?, expiresAt} the
-- Owner approved beyond the connection's allowed paths and methods. They live on the grant row, so
-- revoking or expiring the grant ends them too. NULL means none.
ALTER TABLE grants ADD COLUMN extensions_json TEXT;
