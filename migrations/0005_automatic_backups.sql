CREATE TABLE backup_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  recipient TEXT,
  config_version INTEGER NOT NULL DEFAULT 0,
  revision INTEGER NOT NULL DEFAULT 1,
  success_revision INTEGER NOT NULL DEFAULT 0,
  success_config_version INTEGER NOT NULL DEFAULT -1,
  success_at INTEGER,
  attempt_at INTEGER,
  last_error TEXT,
  object_key TEXT,
  sha256 TEXT,
  lease_token TEXT,
  lease_until INTEGER NOT NULL DEFAULT 0
);
INSERT INTO backup_state (id) VALUES (1);

-- The revision changes atomically with the data, including multi-statement rotations.
CREATE TRIGGER backup_secret_insert AFTER INSERT ON secrets BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_secret_update AFTER UPDATE ON secrets BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_secret_delete AFTER DELETE ON secrets BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_connection_insert AFTER INSERT ON connections BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_connection_update AFTER UPDATE ON connections BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_connection_delete AFTER DELETE ON connections BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
