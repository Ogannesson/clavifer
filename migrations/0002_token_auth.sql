-- Rules read "{" and "}" as a wildcard from this version on, where they were literal before. A URL path
-- spells them %7B and %7D, so no stored rule should hold one; this makes sure, failing the migration
-- (and so the upgrade) on any deny, approval or free rule that does: of a connection, or of a setup or
-- update draft still waiting for the Owner, whose tests ran under the old reading. Rewrite such a rule
-- with %7B and %7D (deny such a draft) in the version installed now, then upgrade again.
CREATE TABLE brace_check (
  n INTEGER NOT NULL CONSTRAINT rules_hold_no_literal_brace CHECK (n = 0)
);
-- An element of a rule list has the list's path: $.deny, $.setup.connections[0].approval,
-- $.update.changes.free.
INSERT INTO brace_check (n)
SELECT COUNT(*) FROM (
  SELECT rule.type, rule.path, rule.value FROM connections, json_tree(connections.policy_json) AS rule
  UNION ALL
  SELECT rule.type, rule.path, rule.value FROM access_requests, json_tree(access_requests.requested_json) AS rule
  WHERE access_requests.status = 'pending' AND access_requests.expires_at > strftime('%s', 'now') * 1000
) WHERE type = 'text' AND (path GLOB '*.deny' OR path GLOB '*.approval' OR path GLOB '*.free')
  AND (instr(value, '{') > 0 OR instr(value, '}') > 0);
DROP TABLE brace_check;
-- A token derived from a secret at a token endpoint, encrypted (apps/worker/src/token.ts), under the
-- digest of what decides it (recipe): connections configured alike share one. It is good only while
-- version is the secret's current version. Like the two tables below it is not in any snapshot and has
-- no trigger, so it never moves the backup revision, and a count of its changes is its own.
CREATE TABLE token_cache (
  secret_id TEXT NOT NULL,
  recipe TEXT NOT NULL,
  version INTEGER NOT NULL,
  envelope_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (secret_id, recipe)
);
-- One exchange per secret at a time, since two recipes may share a refresh token.
CREATE TABLE token_locks (
  secret_id TEXT PRIMARY KEY,
  holder TEXT NOT NULL,
  until INTEGER NOT NULL
);
-- An authorization the Owner started on a connection and has not completed: the digest of its state,
-- the session that started it and the connection's auth_json as it was then.
CREATE TABLE oauth_flows (
  state_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  auth_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
