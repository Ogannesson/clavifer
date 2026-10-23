import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { z } from 'zod';
import {
  secretInput,
  connectionInput,
  grantInput,
  readInput,
  requestInput,
  invokeInput,
  resourceId,
  valuesSchema,
} from '../apps/worker/src/vault.ts';
import { recipientInput } from '../apps/worker/src/export.ts';
import { ownerInput, resetInput } from '../apps/worker/src/setup.ts';
import { startInput, chunkInput, commitInput } from '../apps/worker/src/import.ts';
import { VERSION as version } from '../apps/worker/src/context.ts';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = resolve(root, 'packages/contracts/openapi.json');

function schema(value) {
  const result = z.toJSONSchema(value, { target: 'draft-2020-12', unrepresentable: 'any' });
  delete result.$schema;
  return result;
}
const json = (description, properties = {}, required = []) => ({
  description,
  content: { 'application/json': { schema: { type: 'object', properties, ...(required.length ? { required } : {}) } } },
});
const ref = (name) => ({ $ref: `#/components/schemas/${name}` });
const error = {
  description: 'Stable error code and request ID',
  content: { 'application/json': { schema: ref('Error') } },
};
const owner = [{ OwnerCookie: [] }];
const agent = [{ AgentBearer: [] }];
const both = [{ OwnerCookie: [] }, { AgentBearer: [] }];
// The console's random name for one full export, in the download link and in the status query.
const exportIdParameter = { name: 'id', required: true, schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{22,64}$' } };
// The one-time token the deployment issued, only ever sent in this header.
const bootstrapToken = { name: 'X-Bootstrap-Token', in: 'header', required: true, schema: { type: 'string' } };

const paths = {
  '/healthz': {
    get: {
      operationId: 'health',
      summary: 'Service health',
      description:
        'ok is false when the root key does not match the fingerprints the database recorded; every other route then answers 503 root_key_mismatch. On an initialized instance a root key that cannot be parsed makes every route, this one included, answer 503 invalid_root_key.',
      responses: {
        200: json('Health status', {
          ok: { type: 'boolean' },
          service: { type: 'string' },
          version: { type: 'string' },
          keys: { type: 'string', enum: ['ok', 'mismatch', 'uninitialized'] },
          initialized: { type: 'boolean' },
        }),
      },
    },
  },
  '/api/setup/token': {
    post: {
      operationId: 'checkBootstrapToken',
      summary: 'Check the one-time token without spending it',
      description:
        'Same origin only. Answers for the live token whether the instance is initialized and, once it is, the email the Owner signs in with; any other token is refused with invalid_bootstrap_token.',
      parameters: [bootstrapToken],
      responses: {
        200: json('What the token can do', { initialized: { type: 'boolean' }, email: { type: 'string' } }, [
          'initialized',
        ]),
        401: error,
        403: error,
      },
    },
  },
  '/api/setup/owner': {
    post: {
      operationId: 'createOwner',
      summary: 'Create the Owner of an uninitialized instance',
      description:
        'Same origin only. Spends the token issued for an uninitialized instance (valid 24 hours). In one transaction it empties the instance and writes the Owner, its password, the backup recipient, a new archive identity and the root key fingerprints; the response signs the Owner in. A token that is wrong, expired or already spent is refused with invalid_bootstrap_token, an initialized instance with already_initialized.',
      parameters: [bootstrapToken],
      requestBody: { required: true, content: { 'application/json': { schema: ref('OwnerInput') } } },
      responses: {
        201: json('Created and signed in', { ok: { type: 'boolean' } }),
        400: error,
        401: error,
        403: error,
        409: error,
      },
    },
  },
  '/api/setup/password': {
    post: {
      operationId: 'resetOwnerLogin',
      summary: 'Give the Owner of an initialized instance a new password',
      description:
        'Same origin only. Spends the token issued for an initialized instance (valid 1 hour). Sets the password and removes every Passkey and browser session of the Owner; installations, grants and their refresh tokens stay. An uninitialized instance is refused with not_initialized.',
      parameters: [bootstrapToken],
      requestBody: { required: true, content: { 'application/json': { schema: ref('PasswordReset') } } },
      responses: { 200: json('Reset', { ok: { type: 'boolean' } }), 400: error, 401: error, 403: error, 409: error },
    },
  },
  '/api/setup/import': {
    post: {
      operationId: 'startImport',
      summary: 'Start importing a snapshot into an uninitialized instance',
      description:
        'Same origin only. The console decrypts a clavifer-backup-v1 snapshot in the browser and sends its header and owner records here; the rest follow in chunks and a commit. Spends the token issued for an uninitialized instance (valid 24 hours) and in one transaction empties the instance and records the import, whose id the response returns: like the token it grants the import, and it only ever travels in bodies. A header of a later format, or an Owner password derived with other scrypt parameters, is refused with invalid_snapshot; an initialized instance with already_initialized. A new start replaces any import in progress.',
      parameters: [bootstrapToken],
      requestBody: { required: true, content: { 'application/json': { schema: ref('ImportStart') } } },
      responses: {
        201: json('Import started', { importId: { type: 'string' } }, ['importId']),
        400: error,
        401: error,
        403: error,
        409: error,
      },
    },
  },
  '/api/setup/import/chunk': {
    post: {
      operationId: 'importChunk',
      summary: 'Write a chunk of snapshot records',
      description:
        'Same origin only. Records of the types secret to segment, each checked against the v1 format, written in one transaction with the chunk seq, so a chunk sent again answers written without writing twice. Only structure and references are checked, never the business rules of this version. Credential versions are encrypted under this instance’s root key; an embedded segment is stored under a new key after its SHA-256 matched. A referenced segment (automatic backup) must be in this instance’s bucket with the checksum its record names; when one is not, nothing is written and missing lists them, and the chunk can be sent again with those in skip to go on without them. An import that is no longer the one in progress is refused with import_superseded, before the body is read when no import is in progress at all. Up to 8 MiB and 64 KiB.',
      requestBody: { required: true, content: { 'application/json': { schema: ref('ImportChunk') } } },
      responses: {
        200: json('Written, or the referenced segments that are not in the bucket', {
          written: { type: 'boolean' },
          missing: {
            type: 'array',
            items: { type: 'object', properties: { kind: { type: 'string' }, seq: { type: 'integer' } } },
          },
        }),
        400: error,
        403: error,
        409: error,
        413: error,
      },
    },
  },
  '/api/setup/import/commit': {
    post: {
      operationId: 'commitImport',
      summary: 'Complete an import and initialize the instance',
      description:
        'Same origin only. Takes the settings, archive-identity (or null) and end records. Refused with import_incomplete unless the written records are exactly what end counts (skipped segments included), with snapshot_inconsistent unless every grant and access request names an imported installation, every grant an imported resource, every active connection an active credential with the fields it injects, every active credential exactly its versions, and the segments and remaining rows of each kind are in order. Then one transaction writes the Owner with its password, its Passkeys if the snapshot comes from this hostname, the archive identity (a new one if the snapshot has none), the root key fingerprints, the backup recipient and an instance:import audit row, and removes any token issued meanwhile; the Owner signs in afterwards. It is refused with import_superseded when the import is no longer the one in progress or a chunk arrived after its checks.',
      requestBody: { required: true, content: { 'application/json': { schema: ref('ImportCommit') } } },
      responses: { 200: json('Imported', { ok: { type: 'boolean' } }), 400: error, 403: error, 409: error },
    },
  },
  '/admin/status': {
    get: {
      operationId: 'adminStatus',
      summary: 'Owner dashboard state',
      security: owner,
      responses: {
        200: {
          description: 'Secrets, connections, clients, grants, requests, audit and backup status',
          content: { 'application/json': { schema: ref('AdminStatus') } },
        },
        401: error,
      },
    },
  },
  '/admin/clients': {
    post: {
      operationId: 'createClient',
      summary: 'Create an installation OAuth client',
      security: owner,
      requestBody: { required: true, content: { 'application/json': { schema: ref('ClientInput') } } },
      responses: {
        201: json('Created client', {
          clientId: { type: 'string' },
          name: { type: 'string' },
          server: { type: 'string', format: 'uri' },
        }),
        400: error,
        401: error,
        403: error,
      },
    },
  },
  '/admin/clients/{id}': {
    parameters: [{ $ref: '#/components/parameters/ResourceId' }],
    delete: {
      operationId: 'revokeClient',
      summary: 'Revoke an installation and its grants/tokens, denying its pending requests',
      security: owner,
      responses: { 200: json('Revoked', { ok: { type: 'boolean' } }), 401: error, 403: error },
    },
  },
  '/admin/secrets': {
    post: {
      operationId: 'createSecret',
      summary: 'Create an encrypted secret',
      security: owner,
      requestBody: { required: true, content: { 'application/json': { schema: ref('SecretInput') } } },
      responses: {
        201: json('Created secret', { id: { type: 'string' }, name: { type: 'string' }, version: { type: 'integer' } }),
        400: error,
        401: error,
        403: error,
      },
    },
  },
  '/admin/secrets/{id}': {
    parameters: [{ $ref: '#/components/parameters/ResourceId' }],
    put: {
      operationId: 'rotateSecret',
      summary: 'Rotate a secret with optimistic version check',
      security: owner,
      requestBody: { required: true, content: { 'application/json': { schema: ref('SecretRotationInput') } } },
      responses: {
        200: json('Rotated', { id: { type: 'string' }, version: { type: 'integer' } }),
        400: error,
        401: error,
        403: error,
        409: error,
      },
    },
    delete: {
      operationId: 'deleteSecret',
      summary: 'Delete a secret when no active connection uses it',
      security: owner,
      responses: { 200: json('Deleted', { ok: { type: 'boolean' } }), 401: error, 403: error, 409: error },
    },
  },
  '/admin/connections': {
    post: {
      operationId: 'createConnection',
      summary: 'Create a fixed-origin HTTP connection',
      description:
        'Requests go to origin. hosts lists extra hosts, each a lowercase hostname or "*.suffix" (every host below the suffix, never the suffix itself), and anyHost allows any public HTTPS origin: a one-time approved invocation may name such an origin instead, and nothing else runs there.',
      security: owner,
      requestBody: { required: true, content: { 'application/json': { schema: ref('ConnectionInput') } } },
      responses: { 200: json('Saved connection', { id: { type: 'string' } }), 400: error, 401: error, 403: error },
    },
  },
  '/admin/connections/{id}': {
    parameters: [{ $ref: '#/components/parameters/ResourceId' }],
    put: {
      operationId: 'updateConnection',
      summary: 'Update a fixed-origin HTTP connection',
      security: owner,
      requestBody: { required: true, content: { 'application/json': { schema: ref('ConnectionInput') } } },
      responses: {
        200: json('Saved connection', { id: { type: 'string' } }),
        400: error,
        401: error,
        403: error,
        404: error,
      },
    },
    delete: {
      operationId: 'deleteConnection',
      summary: 'Delete a connection',
      security: owner,
      responses: { 200: json('Deleted', { ok: { type: 'boolean' } }), 401: error, 403: error },
    },
  },
  '/admin/grants': {
    post: {
      operationId: 'grantResources',
      summary: 'Grant resources to an installation',
      security: owner,
      requestBody: { required: true, content: { 'application/json': { schema: ref('GrantRequest') } } },
      responses: { 200: json('Granted', { ok: { type: 'boolean' } }), 400: error, 401: error, 403: error },
    },
  },
  '/admin/grants/{id}': {
    parameters: [{ $ref: '#/components/parameters/ResourceId' }],
    delete: {
      operationId: 'revokeGrant',
      summary: 'Revoke one grant',
      security: owner,
      responses: { 200: json('Revoked', { ok: { type: 'boolean' } }), 401: error, 403: error },
    },
  },
  '/admin/access-requests/{id}/{decision}': {
    parameters: [
      { $ref: '#/components/parameters/RequestId' },
      { name: 'decision', in: 'path', required: true, schema: { type: 'string', enum: ['approve', 'deny'] } },
    ],
    post: {
      operationId: 'decideAccessRequest',
      summary: 'Approve or deny a pending access request',
      description:
        'Approving may only revive a grant that is not live. When a live grant covers the same resource with a different field subset the request is refused with existing_grant_conflict, so the Owner changes the subset in the administration form instead. An approval may set expiresAt (milliseconds, or null until revoked); without it the grant lasts 24 hours. A live grant never loses reach to a shorter expiry. Approving an invocation request ignores the body, unless the invocation names another origin than its connection’s own: then origin has to repeat that origin as stored, or the approval is refused with origin_mismatch. The exact request may run once within 10 minutes. Approving a setup with a credential takes values holding exactly its fields; the credential, every connection and the approval are written in one batch under the ids fixed on submission, so a failure creates none of them; a credential name already taken (also by a deleted credential) is refused with secret_name_taken. Approving an update ignores the body and is refused with connection_changed when the connection changed after submission. Denying ignores the body.',
      security: owner,
      requestBody: { required: false, content: { 'application/json': { schema: ref('AccessDecision') } } },
      responses: {
        200: json('Processed', { ok: { type: 'boolean' } }),
        400: error,
        401: error,
        403: error,
        404: error,
        409: error,
      },
    },
  },
  '/admin/backup/export': {
    get: {
      operationId: 'fullExport',
      summary: 'Stream the complete state of the instance as an age-encrypted v1 full snapshot',
      description:
        'Requires a login within the last 10 minutes and Sec-Fetch-Site: same-origin (a browser download started by the console itself; anything else is refused with cross_site_request). Every sealed segment is embedded; one missing from the bucket or without the checksum its manifest row recorded refuses the export before the first byte (archive_segment_unavailable), as an inconsistent instance does (backup_has_*). The download is whole only once GET /admin/backup/exports/{id} reports complete: a stream that breaks off still ends cleanly for the client.',
      security: owner,
      parameters: [
        { name: 'recipient', in: 'query', required: true, schema: { type: 'string' } },
        { ...exportIdParameter, in: 'query' },
      ],
      responses: {
        200: {
          description: 'Age-encrypted JSON Lines snapshot (clavifer-backup-v1, kind full)',
          content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } },
        },
        400: error,
        401: error,
        403: error,
        409: error,
      },
    },
  },
  '/admin/backup/exports/{id}': {
    get: {
      operationId: 'fullExportStatus',
      summary: 'How far the full export with this id got',
      security: owner,
      parameters: [{ ...exportIdParameter, in: 'path' }],
      responses: {
        200: json(
          'complete after its last byte was written, failed with the code of a refusal, started while it runs or after it broke off, unknown when it never began',
          {
            status: { type: 'string', enum: ['complete', 'started', 'failed', 'unknown'] },
            error: { type: 'string' },
          },
          ['status'],
        ),
        400: error,
        401: error,
      },
    },
  },
  '/admin/backup/status': {
    get: {
      operationId: 'backupStatus',
      summary: 'View automatic backup health',
      security: owner,
      responses: {
        200: {
          description: 'Backup configuration and last result',
          content: { 'application/json': { schema: ref('BackupStatus') } },
        },
        401: error,
      },
    },
  },
  '/admin/backup/config': {
    put: {
      operationId: 'configureBackup',
      summary: 'Set or clear the age recipient used for automatic R2 backups',
      security: owner,
      requestBody: { required: true, content: { 'application/json': { schema: ref('BackupConfigInput') } } },
      responses: {
        200: { description: 'Updated backup status', content: { 'application/json': { schema: ref('BackupStatus') } } },
        400: error,
        401: error,
        403: error,
      },
    },
  },
  '/admin/backup/run': {
    post: {
      operationId: 'runBackup',
      summary: 'Run an immediate automatic backup',
      description:
        'An inconsistent instance is refused (409, backup_has_*) and hot data over 9 MB skips the backup (413, hot_data_over_limit); either way the last saved backup stays current.',
      security: owner,
      responses: {
        200: json('Run result', {
          outcome: { type: 'string' },
          revision: { type: 'integer' },
          sha256: { type: 'string' },
        }),
        401: error,
        409: error,
        413: error,
        503: error,
      },
    },
  },
  '/admin/backup/latest': {
    get: {
      operationId: 'downloadLatestBackup',
      summary: 'Download latest encrypted automatic backup',
      description:
        'A v1 snapshot of kind automatic. It names each sealed segment by its key in the same bucket instead of carrying it, so it is complete only together with that bucket.',
      security: owner,
      responses: {
        200: {
          description: 'Age-encrypted JSON Lines snapshot (clavifer-backup-v1, kind automatic)',
          content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } },
        },
        401: error,
        404: error,
      },
    },
  },
  '/v1/secrets': {
    get: {
      operationId: 'listGrantedResources',
      summary: 'List the secrets granted to this Agent installation and every connection',
      security: agent,
      responses: {
        200: {
          description: 'Granted secret metadata and connection metadata',
          content: { 'application/json': { schema: ref('Metadata') } },
        },
        401: error,
        403: error,
      },
    },
  },
  '/v1/logout': {
    post: {
      operationId: 'logoutInstallation',
      summary: 'Revoke this installation and all of its tokens and grants, denying its pending requests',
      security: agent,
      responses: { 200: json('Revoked', { ok: { type: 'boolean' } }), 401: error },
    },
  },
  '/v1/secrets/{id}/read': {
    parameters: [{ $ref: '#/components/parameters/ResourceId' }],
    post: {
      operationId: 'readSecret',
      summary: 'Read one granted secret',
      description:
        'An empty body returns every field the grant allows. An explicit fields list must stay within the grant (otherwise 403) and must exist in the credential (otherwise 404).',
      security: agent,
      requestBody: { required: false, content: { 'application/json': { schema: ref('SecretReadInput') } } },
      responses: {
        200: {
          description: 'Decrypted secret (never cached)',
          content: { 'application/json': { schema: ref('Secret') } },
        },
        401: error,
        403: error,
        404: error,
      },
    },
  },
  '/v1/access-requests': {
    post: {
      operationId: 'requestAccess',
      summary: 'Request Owner approval for grants, one exact invocation, or a draft of a new or changed connection',
      description:
        'requested holds one of grants, invocation, setup or update. A connection grant may carry paths and/or methods, a temporary scope extension beyond the connection’s allowed paths and methods that ends with the grant. An invocation (body up to 64 KiB) is checked only against the connection and its deny rules on submission, so it may lie outside the allowed paths and methods; once approved, the identical request (method, path as sent, sorted query, forwarded caller headers, body) runs once within 10 minutes through MCP http.request. REST clients add their own headers, so the REST proxy cannot replay it. An invocation may name origin, another origin than the connection’s own that the connection’s hosts or anyHost cover (host_not_allowed otherwise); the approval then runs only with that origin, and the REST proxy, which always goes to the connection’s own origin, cannot name one. A setup drafts a new credential by field names and the 1 to 20 connections using it, each with its own tests and optionally hosts but never anyHost, never an existing secret; an update changes a connection’s name, description, paths, methods or rules, never its origin or auth. Both are checked as the Owner’s forms check them and carry tests the server runs on the draft policy on submission; any mismatch refuses the submission with tests_failed, listing each one. The Owner enters a setup’s credential values on approval; neither carries a grant. A request takes at most 256 KiB as stored, counted on its JSON after escaping (request_too_large). An installation holds at most 20 pending requests and 1 MiB of them as stored: one more is refused with too_many_pending until the Owner decides some, while resubmitting a pending request still returns it.',
      security: agent,
      requestBody: { required: true, content: { 'application/json': { schema: ref('AccessRequest') } } },
      responses: {
        202: json('Pending request', {
          id: { type: 'string' },
          status: { type: 'string' },
          approveUrl: { type: 'string', format: 'uri' },
        }),
        400: error,
        401: error,
        403: error,
        413: error,
        429: error,
      },
    },
  },
  '/v1/access-requests/{id}': {
    parameters: [{ $ref: '#/components/parameters/RequestId' }],
    get: {
      operationId: 'accessStatus',
      summary: 'Read this installation access request status',
      security: agent,
      responses: {
        200: json('Request status', {
          id: { type: 'string' },
          status: { type: 'string', enum: ['pending', 'approved', 'denied', 'expired', 'executed'] },
          expires_at: {
            type: 'integer',
            description:
              'While pending, the deadline for the Owner to decide; for an approved invocation, the deadline to run it once. Absent otherwise.',
          },
          grants: {
            type: 'array',
            description:
              'For an approved grant request, the requested grants as they stand now; a grant that has since ended is left out.',
            items: {
              type: 'object',
              properties: {
                resource_type: { type: 'string', enum: ['secret', 'connection'] },
                resource_id: { type: 'string' },
                permission: { type: 'string' },
                expires_at: {
                  type: ['integer', 'null'],
                  description:
                    'When the grant ends; null means until revoked. A re-grant only lengthens a grant, so this can be later than the period just approved.',
                },
                extensions: { type: 'array', items: { $ref: '#/components/schemas/Extension' } },
              },
            },
          },
          connectionIds: {
            type: 'array',
            items: { type: 'string' },
            description: 'For an approved setup, the connections it created, in the order of its connections.',
          },
          secretId: {
            type: 'string',
            description: 'For an approved setup with a credential, the credential it created.',
          },
        }),
        401: error,
        403: error,
        404: error,
      },
    },
  },
  '/v1/proxy/{connection}/{path}': {
    parameters: [
      { $ref: '#/components/parameters/ConnectionId' },
      {
        name: 'path',
        in: 'path',
        required: true,
        description:
          'Wildcard path below the connection policy, sent upstream as written. %2F and %20 are accepted inside a segment; policy matches the decoded path, which must not contain ";", control characters, or empty, "." or ".." segments.',
        schema: { type: 'string', minLength: 1 },
      },
    ],
    post: {
      operationId: 'proxyPost',
      summary: 'Invoke an approved connection',
      security: agent,
      requestBody: { required: false, content: { '*/*': { schema: { type: 'string', format: 'binary' } } } },
      responses: {
        default: {
          description:
            'Upstream response, streamed without a size limit; the 20 second timeout also aborts a long body',
        },
      },
    },
    get: {
      operationId: 'proxyGet',
      summary: 'Invoke an approved connection',
      security: agent,
      responses: {
        default: {
          description:
            'Upstream response, streamed without a size limit; the 20 second timeout also aborts a long body',
        },
      },
    },
    head: {
      operationId: 'proxyHead',
      summary: 'Read approved connection response headers',
      security: agent,
      responses: { default: { description: 'Upstream response headers' } },
    },
  },
};

const schemas = {
  OwnerInput: schema(ownerInput),
  PasswordReset: schema(resetInput),
  ImportStart: schema(startInput),
  ImportChunk: schema(chunkInput),
  ImportCommit: schema(commitInput),
  SecretInput: schema(secretInput),
  Secret: schema(secretInput.extend({ id: resourceId, version: z.number().int().optional() })),
  SecretReadInput: schema(readInput),
  ClientInput: schema(
    z.object({ name: z.string().min(1).max(100), redirectUris: z.array(z.string().url()).max(10).default([]) }),
  ),
  SecretRotationInput: schema(secretInput.extend({ expectedVersion: z.number().int().positive() })),
  ConnectionInput: schema(connectionInput),
  Grant: schema(grantInput),
  GrantRequest: schema(
    z.object({
      clientId: resourceId,
      grants: z.array(grantInput).min(1).max(20),
      expiresAt: z.number().int().nullable().default(null),
    }),
  ),
  AccessRequest: schema(requestInput),
  AccessDecision: schema(
    z.object({
      expiresAt: z.number().int().nullable().optional(),
      values: valuesSchema.optional(),
      origin: z.string().optional(),
    }),
  ),
  BackupConfigInput: schema(z.object({ recipient: recipientInput.nullable() })),
  InvokeInput: schema(invokeInput),
  Error: {
    type: 'object',
    required: ['error'],
    properties: {
      error: { type: 'string' },
      hint: { type: 'string', description: 'The next step, present on every refusal an Agent can act on.' },
      request_id: { type: 'string' },
    },
    additionalProperties: true,
  },
  Metadata: {
    type: 'object',
    required: ['items', 'connections'],
    properties: {
      items: { type: 'array', items: { $ref: '#/components/schemas/SecretMetadata' } },
      connections: { type: 'array', items: { $ref: '#/components/schemas/ConnectionMetadata' } },
    },
  },
  SecretMetadata: {
    type: 'object',
    properties: {
      id: { type: 'string' },
      name: { type: 'string' },
      description: { type: 'string' },
      current_version: { type: 'integer' },
      fields: {
        type: ['array', 'null'],
        items: { type: 'string' },
        description: 'Fields this installation may read; null means every field.',
      },
      expires_at: { type: ['integer', 'null'], description: 'When the grant ends; null means until revoked.' },
    },
  },
  ConnectionMetadata: {
    type: 'object',
    properties: {
      id: { type: 'string' },
      name: { type: 'string' },
      origin: { type: 'string', format: 'uri' },
      description: { type: 'string', description: 'Usage notes the Owner wrote for Agents.' },
      policy_json: {
        type: 'string',
        description:
          'JSON with the allowed paths and methods (the regular scope) and the deny / approval / free rules ("METHOD /path").',
      },
      granted: {
        type: 'boolean',
        description: 'Whether this installation holds a live connection:invoke grant.',
      },
      expires_at: {
        type: ['integer', 'null'],
        description: 'With a grant, when it ends; null means until revoked.',
      },
      extensions: {
        type: 'array',
        description:
          'Live temporary scope extensions of this installation’s grant. A list the request left out was fixed to the connection’s setting when the grant was approved.',
        items: { $ref: '#/components/schemas/Extension' },
      },
    },
  },
  Extension: {
    type: 'object',
    properties: {
      paths: { type: 'array', items: { type: 'string' } },
      methods: { type: 'array', items: { type: 'string' } },
      expiresAt: { type: ['integer', 'null'] },
    },
  },
  BackupStatus: {
    type: 'object',
    properties: {
      configured: { type: 'boolean' },
      revision: { type: 'integer' },
      savedRevision: { type: 'integer' },
      pending: { type: 'boolean' },
      running: { type: 'boolean' },
      downloadAvailable: { type: 'boolean' },
      storage: { type: 'string' },
      independentCopy: { type: 'boolean' },
      retention: { type: 'object', properties: { daily: { type: 'integer' }, monthly: { type: 'integer' } } },
      retentionError: {
        type: ['string', 'null'],
        description: 'Set when deleting superseded snapshots failed; the backup itself still succeeded.',
      },
      archiveError: {
        type: ['string', 'null'],
        description: 'The error that stopped the last run sealing old audit rows and access requests into archive/.',
      },
      unsealedBytes: {
        type: 'integer',
        description:
          'Bytes of the data sealing never moves out (the Owner, credentials and their versions, connections, installations, grants, the segment manifest). The automatic backup is skipped while the hot data exceeds 9 MB.',
      },
    },
  },
  AdminStatus: {
    type: 'object',
    properties: {
      secrets: { type: 'array' },
      connections: { type: 'array' },
      clients: { type: 'array' },
      grants: { type: 'array' },
      pending: { type: 'array' },
      events: { type: 'array' },
      backup: { $ref: '#/components/schemas/BackupStatus' },
    },
  },
};

const document = {
  openapi: '3.1.0',
  info: {
    title: 'Clavifer REST API',
    version,
    description:
      'Owner administration and Agent resource APIs. Owner routes require the Better Auth session cookie and same-origin writes. Agent routes require an OAuth Bearer token with an installation-specific grant. MCP is a separate Streamable HTTP protocol at /v1/mcp, sharing the /v1 audience. Dynamic client registration is disabled; an Owner creates installation clients through /admin/clients.',
  },
  servers: [{ url: 'https://YOUR-APP-ORIGIN', description: 'Replace with the deployed APP_ORIGIN' }],
  paths,
  components: {
    securitySchemes: {
      OwnerCookie: {
        type: 'apiKey',
        in: 'cookie',
        name: 'better-auth.session_token',
        description:
          'Owner browser session; mutating requests also require Origin equal to APP_ORIGIN. New grants, approving an access request, saving a connection, backup export and recipient changes additionally require a login within the last 10 minutes.',
      },
      AgentBearer: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'OAuth 2.0 access token',
        description:
          'Installation token; secrets are visible only when granted, connections always (never their credential binding).',
      },
    },
    parameters: {
      ResourceId: {
        name: 'id',
        in: 'path',
        required: true,
        schema: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,100}$' },
      },
      ConnectionId: {
        name: 'connection',
        in: 'path',
        required: true,
        schema: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,100}$' },
      },
      RequestId: { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
    },
    schemas,
  },
};

const serialized = JSON.stringify(document, null, 2) + '\n';
await mkdir(dirname(output), { recursive: true });
function validateDocument(value) {
  if (value.openapi !== '3.1.0' || !value.info?.version || !value.paths || !value.components?.schemas)
    throw new Error('invalid OpenAPI root');
  const known = new Set([
    ...Object.keys(value.components.schemas).map((name) => `#/components/schemas/${name}`),
    ...Object.keys(value.components.parameters ?? {}).map((name) => `#/components/parameters/${name}`),
  ]);
  const seen = new Set();
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    if (node.$ref) {
      seen.add(node.$ref);
      return;
    }
    for (const child of Object.values(node)) visit(child);
  };
  visit(value.paths);
  for (const pointer of seen) if (!known.has(pointer)) throw new Error(`unresolved OpenAPI reference: ${pointer}`);
  for (const [path, item] of Object.entries(value.paths))
    for (const [method, operation] of Object.entries(item)) {
      if (method === 'parameters') continue;
      if (!operation.operationId || !operation.responses)
        throw new Error(`operation missing operationId/responses: ${method.toUpperCase()} ${path}`);
      for (const requirement of operation.security ?? [])
        for (const name of Object.keys(requirement))
          if (!value.components.securitySchemes?.[name]) throw new Error(`unknown security scheme: ${name}`);
    }
}
validateDocument(document);
if (process.argv.includes('--check')) {
  const existing = await readFile(output, 'utf8');
  if (existing !== serialized) {
    console.error(`OpenAPI artifact is stale: ${output}`);
    process.exitCode = 1;
  }
} else {
  await writeFile(output, serialized, 'utf8');
}
if (!process.argv.includes('--check')) console.log(`Generated ${output}`);
