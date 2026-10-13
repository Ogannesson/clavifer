-- Retention failures are reported separately so a saved backup never looks failed.
ALTER TABLE backup_state ADD COLUMN retention_error TEXT;
