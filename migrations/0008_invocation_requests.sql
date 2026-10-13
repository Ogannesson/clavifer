-- A request for one exact invocation stores the SHA-256 fingerprint of that request. Once approved,
-- expires_at is the deadline to run it, and consumed_at marks the single run it allows.
ALTER TABLE access_requests ADD COLUMN fingerprint TEXT;
ALTER TABLE access_requests ADD COLUMN consumed_at INTEGER;
