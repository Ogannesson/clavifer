CREATE TABLE "user" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "name" TEXT NOT NULL,
  "email" TEXT UNIQUE NOT NULL,
  "emailVerified" INTEGER NOT NULL,
  "image" TEXT,
  "createdAt" INTEGER NOT NULL,
  "updatedAt" INTEGER NOT NULL
);
CREATE TABLE "session" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "expiresAt" INTEGER NOT NULL,
  "token" TEXT UNIQUE NOT NULL,
  "createdAt" INTEGER NOT NULL,
  "updatedAt" INTEGER NOT NULL,
  "ipAddress" TEXT,
  "userAgent" TEXT,
  "userId" TEXT NOT NULL
);
CREATE INDEX "session_userId_idx" ON "session"("userId");
CREATE TABLE "account" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "accountId" TEXT NOT NULL,
  "providerId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "accessToken" TEXT,
  "refreshToken" TEXT,
  "idToken" TEXT,
  "accessTokenExpiresAt" INTEGER,
  "refreshTokenExpiresAt" INTEGER,
  "scope" TEXT,
  "password" TEXT,
  "createdAt" INTEGER NOT NULL,
  "updatedAt" INTEGER NOT NULL
);
CREATE INDEX "account_userId_idx" ON "account"("userId");
CREATE TABLE "verification" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "identifier" TEXT NOT NULL,
  "value" TEXT NOT NULL,
  "expiresAt" INTEGER NOT NULL,
  "createdAt" INTEGER NOT NULL,
  "updatedAt" INTEGER NOT NULL
);
CREATE INDEX "verification_identifier_idx" ON "verification"("identifier");
CREATE TABLE "jwks" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "publicKey" TEXT NOT NULL,
  "privateKey" TEXT NOT NULL,
  "createdAt" INTEGER NOT NULL,
  "expiresAt" INTEGER,
  "alg" TEXT,
  "crv" TEXT
);
CREATE TABLE "passkey" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "name" TEXT,
  "publicKey" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "credentialID" TEXT NOT NULL,
  "counter" REAL NOT NULL,
  "deviceType" TEXT NOT NULL,
  "backedUp" INTEGER NOT NULL,
  "transports" TEXT,
  "createdAt" INTEGER,
  "aaguid" TEXT
);
CREATE INDEX "passkey_userId_idx" ON "passkey"("userId");
CREATE INDEX "passkey_credentialID_idx" ON "passkey"("credentialID");
CREATE TABLE "oauthClient" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "clientId" TEXT UNIQUE NOT NULL,
  "clientSecret" TEXT,
  "clientDiscoveryId" TEXT,
  "disabled" INTEGER,
  "skipConsent" INTEGER,
  "enableEndSession" INTEGER,
  "subjectType" TEXT,
  "scopes" TEXT,
  "clientCredentialsScopes" TEXT,
  "userId" TEXT,
  "createdAt" INTEGER,
  "updatedAt" INTEGER,
  "name" TEXT,
  "uri" TEXT,
  "icon" TEXT,
  "contacts" TEXT,
  "tos" TEXT,
  "policy" TEXT,
  "softwareId" TEXT,
  "softwareVersion" TEXT,
  "softwareStatement" TEXT,
  "redirectUris" TEXT NOT NULL,
  "postLogoutRedirectUris" TEXT,
  "backchannelLogoutUri" TEXT,
  "backchannelLogoutSessionRequired" INTEGER,
  "tokenEndpointAuthMethod" TEXT,
  "applicationType" TEXT,
  "jwks" TEXT,
  "jwksUri" TEXT,
  "grantTypes" TEXT,
  "responseTypes" TEXT,
  "requirePKCE" INTEGER,
  "dpopBoundAccessTokens" INTEGER,
  "referenceId" TEXT,
  "metadata" TEXT
);
CREATE INDEX "oauthClient_userId_idx" ON "oauthClient"("userId");
CREATE TABLE "oauthResource" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "identifier" TEXT UNIQUE NOT NULL,
  "name" TEXT NOT NULL,
  "accessTokenTtl" REAL,
  "refreshTokenTtl" REAL,
  "signingAlgorithm" TEXT,
  "signingKeyId" TEXT,
  "allowedScopes" TEXT,
  "customClaims" TEXT,
  "dpopBoundAccessTokensRequired" INTEGER,
  "disabled" INTEGER,
  "createdAt" INTEGER,
  "updatedAt" INTEGER,
  "policyVersion" REAL,
  "metadata" TEXT
);
CREATE TABLE "oauthClientResource" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "clientId" TEXT NOT NULL,
  "resourceId" TEXT NOT NULL,
  "metadata" TEXT,
  "createdAt" INTEGER
);
CREATE INDEX "oauthClientResource_clientId_idx" ON "oauthClientResource"("clientId");
CREATE INDEX "oauthClientResource_resourceId_idx" ON "oauthClientResource"("resourceId");
CREATE TABLE "oauthRefreshToken" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "token" TEXT UNIQUE NOT NULL,
  "clientId" TEXT NOT NULL,
  "sessionId" TEXT,
  "userId" TEXT NOT NULL,
  "referenceId" TEXT,
  "authorizationCodeId" TEXT,
  "resources" TEXT,
  "requestedUserInfoClaims" TEXT,
  "expiresAt" INTEGER,
  "createdAt" INTEGER,
  "revoked" INTEGER,
  "rotatedAt" INTEGER,
  "rotationReplayResponse" TEXT,
  "rotationReplayExpiresAt" INTEGER,
  "authTime" INTEGER,
  "confirmation" TEXT,
  "scopes" TEXT NOT NULL
);
CREATE INDEX "oauthRefreshToken_clientId_idx" ON "oauthRefreshToken"("clientId");
CREATE INDEX "oauthRefreshToken_sessionId_idx" ON "oauthRefreshToken"("sessionId");
CREATE INDEX "oauthRefreshToken_userId_idx" ON "oauthRefreshToken"("userId");
CREATE INDEX "oauthRefreshToken_authorizationCodeId_idx" ON "oauthRefreshToken"("authorizationCodeId");
CREATE TABLE "oauthAccessToken" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "token" TEXT UNIQUE,
  "clientId" TEXT NOT NULL,
  "sessionId" TEXT,
  "userId" TEXT,
  "referenceId" TEXT,
  "authorizationCodeId" TEXT,
  "resources" TEXT,
  "requestedUserInfoClaims" TEXT,
  "refreshId" TEXT,
  "expiresAt" INTEGER,
  "createdAt" INTEGER,
  "revoked" INTEGER,
  "confirmation" TEXT,
  "scopes" TEXT NOT NULL
);
CREATE INDEX "oauthAccessToken_clientId_idx" ON "oauthAccessToken"("clientId");
CREATE INDEX "oauthAccessToken_sessionId_idx" ON "oauthAccessToken"("sessionId");
CREATE INDEX "oauthAccessToken_userId_idx" ON "oauthAccessToken"("userId");
CREATE INDEX "oauthAccessToken_authorizationCodeId_idx" ON "oauthAccessToken"("authorizationCodeId");
CREATE INDEX "oauthAccessToken_refreshId_idx" ON "oauthAccessToken"("refreshId");
CREATE TABLE "oauthConsent" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "clientId" TEXT NOT NULL,
  "userId" TEXT,
  "referenceId" TEXT,
  "resources" TEXT,
  "requestedUserInfoClaims" TEXT,
  "scopes" TEXT NOT NULL,
  "createdAt" INTEGER,
  "updatedAt" INTEGER
);
CREATE INDEX "oauthConsent_clientId_idx" ON "oauthConsent"("clientId");
CREATE INDEX "oauthConsent_userId_idx" ON "oauthConsent"("userId");
CREATE TABLE "oauthClientAssertion" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "expiresAt" INTEGER NOT NULL
);
CREATE TABLE "deviceCode" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "deviceCode" TEXT NOT NULL,
  "userCode" TEXT NOT NULL,
  "userId" TEXT,
  "expiresAt" INTEGER NOT NULL,
  "status" TEXT NOT NULL,
  "lastPolledAt" INTEGER,
  "pollingInterval" REAL,
  "clientId" TEXT,
  "scope" TEXT,
  "resources" TEXT,
  "oauthClientId" TEXT
);
CREATE TABLE "rateLimit" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "key" TEXT UNIQUE NOT NULL,
  "count" REAL NOT NULL,
  "lastRequest" REAL NOT NULL
);

CREATE TABLE "secrets" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "owner_id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "description" TEXT,
  "status" TEXT NOT NULL DEFAULT 'active',
  "current_version" INTEGER NOT NULL DEFAULT 0,
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  UNIQUE("owner_id", "name")
);
CREATE TABLE "secret_versions" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "secret_id" TEXT NOT NULL,
  "version" INTEGER NOT NULL,
  "envelope_json" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  UNIQUE("secret_id", "version")
);
CREATE TABLE "connections" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "owner_id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "origin" TEXT NOT NULL,
  "auth_json" TEXT NOT NULL,
  "policy_json" TEXT NOT NULL DEFAULT '{}',
  "status" TEXT NOT NULL DEFAULT 'active',
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  -- Usage notes for Agents (non-secret headers to send, where ids come from); never a secret.
  "description" TEXT NOT NULL DEFAULT '',
  UNIQUE("owner_id", "name")
);
CREATE TABLE "grants" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "owner_id" TEXT NOT NULL,
  "client_id" TEXT NOT NULL,
  "resource_type" TEXT NOT NULL,
  "resource_id" TEXT NOT NULL,
  "permission" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'active',
  "expires_at" INTEGER,
  "created_at" INTEGER NOT NULL,
  -- NULL grants every field of the credential; a JSON array limits the grant to that subset.
  "fields_json" TEXT,
  -- Temporary scope extensions of a connection grant: a JSON array of {paths?, methods?, expiresAt} the
  -- Owner approved beyond the connection's allowed paths and methods. They live on the grant row, so
  -- revoking or expiring the grant ends them too. NULL means none.
  "extensions_json" TEXT,
  UNIQUE("client_id", "resource_type", "resource_id", "permission")
);
CREATE TABLE "access_requests" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "owner_id" TEXT NOT NULL,
  "client_id" TEXT NOT NULL,
  "requested_json" TEXT NOT NULL,
  "reason" TEXT,
  "status" TEXT NOT NULL DEFAULT 'pending',
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  -- A request for one exact invocation stores the SHA-256 fingerprint of that request. Once approved,
  -- expires_at is the deadline to run it, and consumed_at marks the single run it allows.
  "fingerprint" TEXT,
  "consumed_at" INTEGER
);
CREATE TABLE "audit_events" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "owner_id" TEXT NOT NULL,
  "client_id" TEXT,
  "action" TEXT NOT NULL,
  "resource_id" TEXT,
  "result" TEXT NOT NULL,
  "request_id" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL
);
CREATE INDEX "grants_client_idx" ON "grants"("client_id", "status");
CREATE INDEX "audit_created_idx" ON "audit_events"("created_at", "id");
CREATE INDEX "access_requests_created_idx" ON "access_requests"("created_at", "id");
CREATE TABLE "system_state" (
  "key" TEXT PRIMARY KEY NOT NULL,
  "value" TEXT NOT NULL,
  "updated_at" INTEGER NOT NULL
);
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
  lease_until INTEGER NOT NULL DEFAULT 0,
  -- Retention failures are reported separately so a saved backup never looks failed.
  retention_error TEXT,
  -- The error that stopped the last sealing run, until a run ends without one.
  archive_error TEXT
);
-- Sealed segments: immutable age files under archive/ in R2, each a contiguous (created_at, id) range
-- of one table's rows. Neither the rows nor the objects ever come back.
CREATE TABLE "archive_segments" (
  "kind" TEXT NOT NULL,
  "seq" INTEGER NOT NULL,
  "object_key" TEXT NOT NULL,
  "sha256" TEXT NOT NULL,
  "first_at" INTEGER NOT NULL,
  "first_id" TEXT NOT NULL,
  "last_at" INTEGER NOT NULL,
  "last_id" TEXT NOT NULL,
  "rows" INTEGER NOT NULL,
  "created_at" INTEGER NOT NULL,
  PRIMARY KEY ("kind", "seq")
);
-- The chunks an import in progress has written (system_state import_id names the import), each with the
-- referenced segments the Owner chose to import without. Only one import is ever in progress, and its
-- commit or the next initialization deletes them.
CREATE TABLE "import_chunks" (
  "seq" INTEGER PRIMARY KEY NOT NULL,
  "skipped" TEXT NOT NULL DEFAULT '[]'
);
INSERT INTO backup_state (id) VALUES (1);
CREATE TRIGGER backup_secret_insert AFTER INSERT ON secrets BEGIN
  -- The revision counts changes to what a snapshot carries; the automatic backup runs only when it moved
  -- (and once a day). Apart from a Passkey's, no delete counts: sealing deletes rows in the batch that
  -- inserts their manifest row, and deleting a credential's versions goes with the update of its row. A
  -- Passkey's counter, which every sign-in updates, and the system's own audit rows do not count either.
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_secret_update AFTER UPDATE ON secrets BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_secret_version_insert AFTER INSERT ON secret_versions BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_secret_version_update AFTER UPDATE ON secret_versions BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_connection_insert AFTER INSERT ON connections BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_connection_update AFTER UPDATE ON connections BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_installation_insert AFTER INSERT ON "oauthClient" BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_installation_update AFTER UPDATE ON "oauthClient" BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_grant_insert AFTER INSERT ON grants BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_grant_update AFTER UPDATE ON grants BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_request_insert AFTER INSERT ON access_requests BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_request_update AFTER UPDATE ON access_requests BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_audit_insert AFTER INSERT ON audit_events WHEN NEW.client_id IS NOT 'system' BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_segment_insert AFTER INSERT ON archive_segments BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_passkey_insert AFTER INSERT ON "passkey" BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_passkey_delete AFTER DELETE ON "passkey" BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_passkey_rename AFTER UPDATE ON "passkey" WHEN NEW."name" IS NOT OLD."name" BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_password_update AFTER UPDATE ON "account" WHEN NEW."password" IS NOT OLD."password" BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER backup_owner_update AFTER UPDATE ON "user"
  WHEN NEW."email" IS NOT OLD."email" OR NEW."name" IS NOT OLD."name" OR NEW."image" IS NOT OLD."image" BEGIN
  UPDATE backup_state SET revision = revision + 1 WHERE id = 1;
END;
