CREATE TABLE IF NOT EXISTS "secrets" (
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
CREATE TABLE IF NOT EXISTS "secret_versions" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "secret_id" TEXT NOT NULL,
  "version" INTEGER NOT NULL,
  "envelope_json" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  UNIQUE("secret_id", "version")
);
CREATE TABLE IF NOT EXISTS "connections" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "owner_id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "origin" TEXT NOT NULL,
  "auth_json" TEXT NOT NULL,
  "policy_json" TEXT NOT NULL DEFAULT '{}',
  "status" TEXT NOT NULL DEFAULT 'active',
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  UNIQUE("owner_id", "name")
);
CREATE TABLE IF NOT EXISTS "grants" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "owner_id" TEXT NOT NULL,
  "client_id" TEXT NOT NULL,
  "resource_type" TEXT NOT NULL,
  "resource_id" TEXT NOT NULL,
  "permission" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'active',
  "expires_at" INTEGER,
  "created_at" INTEGER NOT NULL,
  UNIQUE("client_id", "resource_type", "resource_id", "permission")
);
CREATE TABLE IF NOT EXISTS "access_requests" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "owner_id" TEXT NOT NULL,
  "client_id" TEXT NOT NULL,
  "requested_json" TEXT NOT NULL,
  "reason" TEXT,
  "status" TEXT NOT NULL DEFAULT 'pending',
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS "audit_events" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "owner_id" TEXT NOT NULL,
  "client_id" TEXT,
  "action" TEXT NOT NULL,
  "resource_id" TEXT,
  "result" TEXT NOT NULL,
  "request_id" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS "grants_client_idx" ON "grants"("client_id", "status");
CREATE INDEX IF NOT EXISTS "audit_created_idx" ON "audit_events"("created_at");
