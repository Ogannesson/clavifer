import { z } from 'zod';
import { Buffer } from 'node:buffer';
import { assert, Fault } from '../../../packages/core/errors';
import { decryptSecret } from '../../../packages/core/crypto';
import {
  canonicalPath,
  checkPath,
  targetUrl,
  upstreamHeaders,
  credentialHeaderName,
  appendQuery,
  matchRule,
  parseRule,
  matchHost,
  validHost,
  METHODS,
  QUERY_TOO_LARGE,
} from '../../../packages/core/proxy';
import { type Bindings, type Principal, now, id, rootKeys, audit, boundedBytes } from './context';

// Messages on these schemas reach an Agent as the hint of invalid_arguments, naming what to fix.
export const resourceId = z
  .string()
  .regex(/^[a-zA-Z0-9_-]{1,100}$/, 'an id is 1-100 letters, digits, "_" or "-"; copy it from credentials.list');
export const valuesSchema = z
  .record(z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$/), z.string().min(1).max(16384))
  .refine((v) => Object.keys(v).length > 0 && Object.keys(v).length <= 20);
export const secretInput = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().max(1000).default(''),
  values: valuesSchema,
});
const authField = z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$/);
export const authInput = z.discriminatedUnion('type', [
  z.object({ type: z.literal('none') }),
  z.object({ type: z.literal('bearer'), secretId: resourceId, field: authField }),
  z.object({
    type: z.literal('header'),
    secretId: resourceId,
    field: authField,
    name: z.string().refine(credentialHeaderName),
  }),
  z.object({ type: z.literal('basic'), secretId: resourceId, usernameField: authField, passwordField: authField }),
  z.object({
    type: z.literal('query'),
    secretId: resourceId,
    field: authField,
    name: z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_.~-]{0,63}$/),
  }),
]);
// A setup creates its credential, so its auth names fields of that credential and never a secretId:
// binding a stored secret would let an Agent send it to an origin of its choosing.
const draftAuth = z.discriminatedUnion('type', [
  z.strictObject(authInput.options[0].shape),
  z.strictObject(authInput.options[1].omit({ secretId: true }).shape),
  z.strictObject(authInput.options[2].omit({ secretId: true }).shape),
  z.strictObject(authInput.options[3].omit({ secretId: true }).shape),
  z.strictObject(authInput.options[4].omit({ secretId: true }).shape),
]);
export function authFields(auth: z.infer<typeof draftAuth>): string[] {
  return auth.type === 'none' ? [] : auth.type === 'basic' ? [auth.usernameField, auth.passwordField] : [auth.field];
}
export function validateAuthBinding(auth: z.infer<typeof authInput>, values: Record<string, string>) {
  for (const field of authFields(auth))
    assert(
      Object.hasOwn(values, field) && typeof values[field] === 'string' && values[field].length > 0,
      'secret_field_not_found',
      404,
    );
  if (auth.type === 'basic') {
    assert(
      !/[:\x00-\x1f\x7f]/.test(values[auth.usernameField]) && !/[\x00-\x1f\x7f]/.test(values[auth.passwordField]),
      'invalid_basic_credential',
    );
  } else if (auth.type === 'bearer' || auth.type === 'header') {
    const value = values[auth.field];
    assert(/^[\x20-\x7e]+$/.test(value) && value.trim() === value, 'invalid_header_credential');
  }
}
const methodList = z.array(z.enum(METHODS)).min(1).max(7);
export const connectionInput = z.object({
  name: z.string().trim().min(1).max(120),
  origin: z.string().url(),
  // Usage notes written for Agents, such as a non-secret header every request needs.
  description: z.string().max(2000).default(''),
  // Allowed paths and methods form the regular scope; see invoke for what applies outside it.
  paths: z.array(z.string().min(1).max(300)).min(1).max(30),
  methods: methodList.default(['GET', 'HEAD']),
  // Each line is "METHOD /path" (see parseRule): deny always refuses, approval needs a one-time
  // Owner approval of the exact request, free runs without any grant.
  // Line length and count are checked in policyJson, so an error can name the list and line.
  deny: z.array(z.string()).default([]),
  approval: z.array(z.string()).default([]),
  free: z.array(z.string()).default([]),
  // Where else a one-time approval may send a request with this connection's credential: the extra
  // hosts (each a hostname or "*.suffix", see validHost; checked in policyJson, so an error can name
  // the line), or with anyHost any public HTTPS origin. See otherOrigin and invoke.
  hosts: z.array(z.string()).max(20).default([]),
  anyHost: z.boolean().default(false),
  auth: authInput.default({ type: 'none' }),
});
const RULE_LIMIT = 50;
// A bare path in a free rule means a read (GET, and so HEAD); in deny or approval it means any method.
const IMPLICIT_METHOD = { deny: '*', approval: '*', free: 'GET' } as const;
// A stored policy is read as it is: only paths and methods are certain to be there. An absent rule
// list has no rule, absent hosts no extra host, and absent anyHost means not any host.
export type ConnectionPolicy = Pick<z.infer<typeof connectionInput>, 'paths' | 'methods'> &
  Partial<Pick<z.infer<typeof connectionInput>, 'deny' | 'approval' | 'free' | 'hosts' | 'anyHost'>>;
/** An allowed path or a grant extension path: a literal prefix, never a glob. */
function prefixPath(path: string) {
  assert(
    !path.includes('*'),
    'use_path_prefix_not_glob',
    400,
    'A path here is a literal prefix without "*": "/v1/items" covers /v1/items and everything below it.',
  );
  return checkPath(path);
}
/** Validates a connection policy being saved or proposed in a draft and returns it with each rule normalized. allowLocal
 * is the local deployment's exception for an extra host, the one targetUrl makes for an origin. */
export function policyJson(c: Required<ConnectionPolicy>, allowLocal = false) {
  c.paths.forEach((path, i) => {
    try {
      prefixPath(path);
    } catch (e) {
      const { code, status, message } = e as Fault;
      throw new Fault(code, status, `paths line ${i + 1}: ${message}`);
    }
  });
  c.hosts.forEach((host, i) => assert(validHost(host, allowLocal), 'invalid_host', 400, `hosts line ${i + 1}`));
  // The hint names the list and the 1-based line, e.g. "deny line 3", so the form can point at it.
  const rules = (kind: keyof typeof IMPLICIT_METHOD) => {
    assert(c[kind].length <= RULE_LIMIT, 'too_many_rules', 400, kind);
    return c[kind].map((text, i) => {
      try {
        return parseRule(text, IMPLICIT_METHOD[kind]).text;
      } catch {
        throw new Fault('invalid_rule', 400, `${kind} line ${i + 1}`);
      }
    });
  };
  return JSON.stringify({
    paths: c.paths,
    methods: c.methods,
    deny: rules('deny'),
    approval: rules('approval'),
    free: rules('free'),
    hosts: c.hosts,
    anyHost: c.anyHost,
  });
}
// fields limits a secret:read grant to a subset of the credential; absent means every field.
// paths and methods give a connection grant a temporary scope extension: the requests with one of
// these path prefixes and methods. It covers requests outside the regular scope and ends with the
// grant; it never changes the connection.
export const grantInput = z
  .object({
    resourceType: z.enum(['secret', 'connection']),
    resourceId,
    permission: z.enum(['secret:read', 'connection:invoke']),
    fields: z.array(authField).min(1).max(20).optional(),
    paths: z.array(z.string().min(1).max(300).refine(prefixPath)).min(1).max(30).optional(),
    methods: methodList.optional(),
  })
  .refine((g) => g.permission === (g.resourceType === 'secret' ? 'secret:read' : 'connection:invoke'), {
    message: 'permission is secret:read for a secret and connection:invoke for a connection',
  })
  .refine((g) => !g.fields || g.resourceType === 'secret', { message: 'fields applies only to secret grants' })
  .refine((g) => (!g.paths && !g.methods) || g.resourceType === 'connection', {
    message: 'paths and methods apply only to connection grants',
  });
export type Extension = { paths: string[]; methods: string[]; expiresAt: number | null };
/** The extension a connection grant asks for, lasting until expiresAt, or null when it asks for none.
 * A list the grant leaves out is copied from the connection now, so a later edit of the connection
 * never widens an extension the Owner already approved. */
export function requestedExtension(
  g: z.infer<typeof grantInput>,
  policyJson: string | null,
  expiresAt: number | null,
): Extension | null {
  if (!g.paths && !g.methods) return null;
  const policy = JSON.parse(policyJson!) as ConnectionPolicy;
  return { paths: g.paths ?? policy.paths, methods: g.methods ?? policy.methods ?? ['GET', 'HEAD'], expiresAt };
}
/** A grant row's extensions that have not expired. */
export const liveExtensions = (value: string | null | undefined) =>
  value ? (JSON.parse(value) as Extension[]).filter((e) => e.expiresAt === null || e.expiresAt > now()) : [];
export const readInput = z.object({ fields: z.array(authField).min(1).max(20).optional() });
const requestHeaders = z
  .record(z.string().min(1).max(256), z.string().max(8192))
  .refine((v) => Object.keys(v).length <= 100, { message: 'at most 100 headers' });
const requestQuery = z
  .record(z.string().min(1).max(256), z.string().max(8192))
  .refine((v) => Object.keys(v).length <= 100, { message: 'at most 100 query parameters; paginate or filter less' });
// The body is bounded in bytes by invoke, so an oversized one answers body_too_large with its hint.
// origin sends the request to another origin than the connection's own: one of its extra hosts, or any
// public HTTPS origin when the connection reaches any host. It runs only on a one-time approval.
export const invokeInput = z.object({
  connection: resourceId,
  origin: z.string().url().optional(),
  path: z.string().max(2048).default('/'),
  method: z.enum(METHODS).default('GET'),
  headers: requestHeaders.optional(),
  query: requestQuery.optional(),
  body: z.string().optional(),
});
export type InvokeRequest = Omit<z.infer<typeof invokeInput>, 'body' | 'query'> & {
  body?: string | Uint8Array;
  query?: Record<string, string> | [string, string][];
};
export const VERDICTS = [
  'run',
  'path_denied',
  'approval_required',
  'path_not_allowed',
  'method_not_allowed',
  'grant_required',
] as const;
export type Decision = { code: (typeof VERDICTS)[number]; rule?: string };
/** What a connection's policy decides for one request before any one-time approval: run it, or the code
 * that refuses it (path_denied with the deny rule it hit). It reads neither the database nor the
 * upstream, so invoke and the tests of a draft share it; grant is the live extensions of the caller's
 * connection:invoke grant, or null without one.
 * Order: deny rules, then approval rules. Inside the regular scope (allowed paths and methods) a free
 * rule or a grant runs the request; outside it only a live extension of the grant that covers it. A
 * one-time approval runs any refused request except a denied one, so a deny rule also stops a request
 * the Owner approved once, and an approval rule stops a grant and its extensions alike. */
export function decide(
  policy: ConnectionPolicy,
  method: (typeof METHODS)[number],
  rawPath: string,
  grant: Extension[] | null,
): Decision {
  const path = canonicalPath(rawPath);
  const denied = policy.deny?.find((rule) => matchRule([rule], method, path));
  if (denied) return { code: 'path_denied', rule: denied };
  if (matchRule(policy.approval, method, path)) return { code: 'approval_required' };
  const inPaths = checkPath(rawPath, policy.paths);
  const inScope = inPaths && (policy.methods ?? ['GET', 'HEAD']).includes(method);
  if (inScope && matchRule(policy.free, method, path)) return { code: 'run' };
  if (grant && (inScope || grant.some((e) => checkPath(rawPath, e.paths) && e.methods.includes(method))))
    return { code: 'run' };
  return { code: !inPaths ? 'path_not_allowed' : !inScope ? 'method_not_allowed' : 'grant_required' };
}
// A test of a draft policy: the decision for this request without a grant, or with one that carries
// no extension. Its path passes the checks a real request's path does.
const policyTests = z
  .array(
    z.strictObject({
      method: z.enum(METHODS),
      path: z
        .string()
        .max(2048)
        .superRefine((path, ctx) => {
          try {
            canonicalPath(path);
          } catch (e) {
            ctx.addIssue({ code: 'custom', message: (e as Fault).message });
          }
        }),
      grant: z.boolean().default(false),
      expect: z.enum(VERDICTS),
    }),
  )
  .min(1)
  .max(100);
type PolicyTest = z.infer<typeof policyTests>[number];
const verdicts = (policy: ConnectionPolicy, tests: PolicyTest[]) =>
  tests.map((t) => decide(policy, t.method, t.path, t.grant ? [] : null));
/** The tests a draft policy does not decide as expected, each named by its place in the draft. */
const mismatches = (policy: ConnectionPolicy, tests: PolicyTest[], at = 'tests') =>
  verdicts(policy, tests).flatMap((d, i) => {
    const t = tests[i];
    return d.code === t.expect
      ? []
      : [
          `${at}.${i} ${t.method} ${t.path} ${t.grant ? 'with' : 'without'} a grant: expected ${t.expect}, got ${d.code}${d.rule ? ` from "deny ${d.rule}"` : ''}`,
        ];
  });
/** Refuses a draft unless every one of its tests matched, naming each mismatch. */
function assertTests(failed: string[], total: number) {
  assert(
    !failed.length,
    'tests_failed',
    400,
    `${failed.length} of ${total} tests do not match the draft policy; fix the draft or the expectation and submit again. ${failed.join('; ')}`,
  );
}
// A setup proposes a credential by its field names (the Owner enters the values on approval) and the
// connections that use it, or connections without a credential. Each connection carries its own tests:
// a method and a path alone would not say which connection they are meant for. A connection may list
// extra hosts, which the Owner reviews with the draft, but reaching any host is the Owner's alone to set.
const setupInput = z
  .strictObject({
    secret: z
      .strictObject({
        name: secretInput.shape.name,
        description: secretInput.shape.description,
        fields: z
          .array(authField)
          .min(1)
          .max(20)
          .refine((f) => new Set(f).size === f.length, { message: 'field names must be unique' }),
      })
      .optional(),
    connections: z
      .array(
        connectionInput.extend({
          auth: draftAuth.default({ type: 'none' }),
          anyHost: z
            .literal(false, {
              message:
                'only the Owner can let a connection reach any host, on the connections page; list hosts instead',
            })
            .default(false),
          tests: policyTests,
        }),
      )
      .min(1)
      .max(20)
      .refine((c) => new Set(c.map((x) => x.name)).size === c.length, { message: 'connection names must be unique' }),
  })
  .superRefine((s, ctx) =>
    s.connections.forEach((c, i) => {
      const message =
        (c.auth.type === 'none') === !!s.secret
          ? 'a setup with secret injects it in every connection, so none of them has auth none; a setup without secret has auth none in every connection'
          : authFields(c.auth).every((field) => s.secret?.fields.includes(field))
            ? null
            : 'every field auth names must be listed in secret.fields';
      if (message) ctx.addIssue({ code: 'custom', path: ['connections', i, 'auth'], message });
    }),
  );
// An update changes only what never decides where a credential goes: origin and auth stay as they are.
const shape = connectionInput.shape;
const updateInput = z.strictObject({
  connection: resourceId,
  changes: z
    .strictObject({
      name: shape.name.optional(),
      description: shape.description.unwrap().optional(),
      paths: shape.paths.optional(),
      methods: shape.methods.unwrap().optional(),
      deny: shape.deny.unwrap().optional(),
      approval: shape.approval.unwrap().optional(),
      free: shape.free.unwrap().optional(),
    })
    .refine((c) => Object.keys(c).length > 0, {
      message: 'changes holds at least one of name, description, paths, methods, deny, approval, free',
    }),
  tests: policyTests,
});
// A request carries exactly one of: grants; one exact invocation for a one-time approval; a setup of a
// new credential and its connections; an update of a connection. An invocation names its method and path, so
// the Owner never approves a request filled in by default.
export const requestInput = z.object({
  requested: z
    .strictObject({
      grants: z.array(grantInput).min(1).max(20).optional(),
      invocation: invokeInput.extend({ path: z.string().max(2048), method: z.enum(METHODS) }).optional(),
      setup: setupInput.optional(),
      update: updateInput.optional(),
    })
    .refine((r) => [r.grants, r.invocation, r.setup, r.update].filter(Boolean).length === 1, {
      message: 'requested holds exactly one of grants or invocation or setup or update',
    }),
  reason: z.string().max(500).default(''),
});
/** A request as stored: what the Agent asked for, plus what the server fixed on submission. A setup
 * gets the ids of what approval creates, connectionIds in the order of its connections; an update
 * records the connection's updated_at, which approval requires unchanged, and the tests' decisions
 * under the current policy for the Owner's comparison. */
export type StoredRequest = z.infer<typeof requestInput>['requested'] & {
  ids?: { secretId?: string; connectionIds: string[] };
  current?: Decision['code'][];
  updatedAt?: number;
};
export type ConnectionRow = {
  name: string;
  origin: string;
  description: string;
  auth_json: string;
  policy_json: string;
  updated_at: number;
};
/** A connection with an update's changes applied, checked as the Owner's form checks it. Its extra
 * hosts and anyHost are the connection's own: an update cannot name them. */
export const withChanges = (conn: ConnectionRow, changes: z.infer<typeof updateInput>['changes']) =>
  connectionInput.parse({
    name: conn.name,
    origin: conn.origin,
    description: conn.description,
    ...(JSON.parse(conn.policy_json) as ConnectionPolicy),
    auth: JSON.parse(conn.auth_json),
    ...changes,
  });
export async function assertGrant(env: Bindings, p: Principal, type: string, rid: string, permission: string) {
  assert(p.scopes.includes(permission), 'insufficient_scope', 403);
  const grant = await liveGrant(env, p, type, rid, permission);
  assert(grant, 'insufficient_scope', 403);
  return grant;
}
const liveGrant = (env: Bindings, p: Principal, type: string, rid: string, permission: string) =>
  env.DB.prepare(
    'SELECT fields_json,extensions_json FROM grants WHERE owner_id=? AND client_id=? AND resource_type=? AND resource_id=? AND permission=? AND status=? AND (expires_at IS NULL OR expires_at>?)',
  )
    .bind(p.userId, p.clientId, type, rid, permission, 'active', now())
    .first<{ fields_json: string | null; extensions_json: string | null }>();
const grantedFields = (value: string | null | undefined) => (value ? (JSON.parse(value) as string[]) : null);
export async function metadata(env: Bindings, p: Principal) {
  assert(p.scopes.includes('metadata:list'), 'insufficient_scope', 403);
  // One grant row per (client, resource, permission) by unique constraint, so the join projects its field subset.
  const secrets = await env.DB.prepare(
    "SELECT s.id,s.name,s.description,s.current_version,g.fields_json,g.expires_at FROM secrets s JOIN grants g ON g.resource_id=s.id AND g.owner_id=s.owner_id AND g.client_id=? AND g.resource_type='secret' AND g.permission='secret:read' AND g.status='active' AND (g.expires_at IS NULL OR g.expires_at>?) WHERE s.owner_id=? AND s.status='active' ORDER BY s.name",
  )
    .bind(p.clientId, now(), p.userId)
    .all<{
      id: string;
      name: string;
      description: string;
      current_version: number;
      fields_json: string | null;
      expires_at: number | null;
    }>();
  // Every connection is listed, so an installation can ask for one it holds no grant for; it sees its
  // own grant and extensions, never the binding, the credential or another installation's grants.
  const connections = await env.DB.prepare(
    "SELECT s.id,s.name,s.origin,s.description,s.policy_json,g.id IS NOT NULL AS granted,g.expires_at,g.extensions_json FROM connections s LEFT JOIN grants g ON g.client_id=? AND g.owner_id=s.owner_id AND g.resource_type='connection' AND g.resource_id=s.id AND g.permission='connection:invoke' AND g.status='active' AND (g.expires_at IS NULL OR g.expires_at>?) WHERE s.owner_id=? AND s.status='active' ORDER BY s.name",
  )
    .bind(p.clientId, now(), p.userId)
    .all<{
      id: string;
      name: string;
      origin: string;
      description: string;
      policy_json: string;
      granted: number;
      expires_at: number | null;
      extensions_json: string | null;
    }>();
  return {
    items: secrets.results.map(({ fields_json, ...s }) => ({ ...s, fields: grantedFields(fields_json) })),
    connections: connections.results.map(({ extensions_json, ...c }) => ({
      ...c,
      granted: !!c.granted,
      extensions: liveExtensions(extensions_json),
    })),
  };
}
export async function boundSecret(env: Bindings, owner: string, sid: string) {
  const row = await env.DB.prepare(
    "SELECT s.current_version,v.envelope_json FROM secrets s JOIN secret_versions v ON v.secret_id=s.id AND v.version=s.current_version WHERE s.id=? AND s.owner_id=? AND s.status='active'",
  )
    .bind(sid, owner)
    .first<{ current_version: number; envelope_json: string }>();
  assert(row, 'secret_not_found', 404);
  return {
    version: row.current_version,
    values: await decryptSecret(
      rootKeys(env),
      { ownerId: owner, secretId: sid, version: row.current_version },
      JSON.parse(row.envelope_json),
    ),
  };
}
export async function readSecret(env: Bindings, p: Principal, sid: string, requested?: string[]) {
  const allowed = grantedFields((await assertGrant(env, p, 'secret', sid, 'secret:read')).fields_json);
  if (requested && allowed)
    assert(
      requested.every((field) => allowed.includes(field)),
      'insufficient_scope',
      403,
    );
  await audit(env, p.clientId, 'secret:read', sid, 'authorized');
  const secret = await boundSecret(env, p.userId, sid);
  const selected = requested ?? allowed;
  if (!selected) return { id: sid, ...secret };
  // An explicit request names fields the caller expects; a grant subset only narrows what is returned.
  if (requested)
    for (const field of requested) assert(Object.hasOwn(secret.values, field), 'secret_field_not_found', 404);
  return {
    id: sid,
    version: secret.version,
    values: Object.fromEntries(Object.entries(secret.values).filter(([field]) => selected.includes(field))),
  };
}
export async function accessRequest(env: Bindings, p: Principal, input: unknown, origin: string) {
  assert(p.scopes.includes('access:request'), 'insufficient_scope', 403);
  const body = requestInput.parse(input);
  let fingerprint: string | null = null;
  // Submission checks the input, the connection and its deny rules, which no approval can override.
  // Allowed paths and methods are not checked: a one-time approval may run outside the regular scope.
  // A grant request only has to name resources that exist.
  for (const g of body.requested.grants ?? []) {
    const secret = g.resourceType === 'secret';
    assert(
      await env.DB.prepare(
        `SELECT 1 FROM ${secret ? 'secrets' : 'connections'} WHERE id=? AND owner_id=? AND status='active'`,
      )
        .bind(g.resourceId, p.userId)
        .first(),
      secret ? 'secret_not_found' : 'connection_not_found',
      404,
      secret ? 'No active secret has this id. Ask the user which stored secret the task needs.' : connectionNotFound,
    );
  }
  if (body.requested.invocation) {
    const call = body.requested.invocation;
    const bytes = new TextEncoder().encode(call.body ?? '');
    assert(
      bytes.byteLength <= 65536,
      'body_too_large',
      413,
      'An invocation request carries at most 64 KiB of body. Split the work into smaller requests; upload large files with the host’s own tools.',
    );
    assert(!['GET', 'HEAD'].includes(call.method) || !bytes.byteLength, 'body_not_allowed');
    // The Owner reviews every header and the console lists pending requests whole, so headers are
    // capped in total, not just per entry.
    assert(
      new TextEncoder().encode(JSON.stringify(call.headers ?? {})).byteLength <= 16384,
      'headers_too_large',
      413,
      'An invocation request carries at most 16 KiB of headers in total. Send only the headers the upstream needs.',
    );
    const { conn, policy } = await activeConnection(env, p.userId, call.connection);
    // Stored as URL writes it and left out when it is the connection's own, so the Owner reviews, and
    // the fingerprint holds, the one spelling invoke compares.
    call.origin = otherOrigin(env, conn, policy, call.origin);
    const decision = decide(policy, call.method, call.path, null);
    if (decision.code === 'path_denied') throw refusal(decision);
    appendQuery(
      targetUrl(call.origin ?? conn.origin, call.path, env.ALLOW_LOCAL_HTTP === 'true'),
      Object.entries(call.query ?? {}),
    );
    fingerprint = await requestFingerprint(
      call.connection,
      call.method,
      call.path,
      Object.entries(call.query ?? {}),
      upstreamHeaders(call.headers ?? {}),
      bytes,
      call.origin,
    );
  }
  const { setup, update } = body.requested;
  const stored: StoredRequest = setup
    ? await setupRequest(env, p.userId, setup)
    : update
      ? await updateRequest(env, p.userId, update)
      : body.requested;
  const requested = JSON.stringify(stored);
  // They are fixed on submission, so access.status can name them once the Owner approves.
  const ids = setup && {
    ...(setup.secret ? { secretId: id() } : {}),
    connectionIds: setup.connections.map(() => id()),
  };
  const value = ids ? JSON.stringify({ ...stored, ids }) : requested;
  // Counted as stored, after JSON escaping, which is what the database, the console and every snapshot hold.
  const size = new TextEncoder().encode(value + body.reason).byteLength;
  assert(
    size <= 256 * 1024,
    'request_too_large',
    413,
    `This request takes ${size} bytes as stored and at most 262144 (256 KiB) are accepted. The size counted is the stored JSON, where escaping can grow text several times (64 KiB of control characters takes about 393 KB). Split the draft into smaller requests or trim its tests, descriptions and body.`,
  );
  // The ids of what a setup creates differ on every submission, so a resubmission is matched without them.
  const old = await env.DB.prepare(
    "SELECT id FROM access_requests WHERE client_id=? AND status='pending' AND expires_at>? AND json_remove(requested_json,'$.ids')=json(?) LIMIT 1",
  )
    .bind(p.clientId, now(), requested)
    .first<{ id: string }>();
  const rid = old?.id ?? id();
  if (!old) {
    // The Owner reads every pending request, so one installation holds at most 20 at a time and 1 MiB
    // of them as stored.
    const result = await env.DB.prepare(
      "INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at,fingerprint) SELECT ?,?,?,?,?,?,?,?,? FROM (SELECT COUNT(*) AS n,IFNULL(SUM(length(CAST(requested_json AS BLOB))+IFNULL(length(CAST(reason AS BLOB)),0)),0) AS bytes FROM access_requests WHERE client_id=? AND status='pending' AND expires_at>?) WHERE n<20 AND bytes+?<=1048576",
    )
      .bind(
        rid,
        p.userId,
        p.clientId,
        value,
        body.reason,
        'pending',
        now(),
        now() + 86400000,
        fingerprint,
        p.clientId,
        now(),
        size,
      )
      .run();
    // D1 counts the row the backup revision trigger updates as a change too.
    if (result.meta.changes === 0) {
      const waiting = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM access_requests WHERE client_id=? AND status='pending' AND expires_at>?",
      )
        .bind(p.clientId, now())
        .first<{ n: number }>();
      throw new Fault(
        'too_many_pending',
        429,
        waiting!.n >= 20
          ? 'This installation already has 20 requests waiting for the Owner. Wait for the Owner to decide them and tell the user; do not submit this request again until then.'
          : `This request would bring the requests this installation has waiting for the Owner over 1 MiB as stored (this one takes ${size} bytes). Wait for the Owner to decide some and tell the user; a smaller request may still fit.`,
      );
    }
  }
  return { id: rid, status: 'pending', approveUrl: `${origin}/?tab=access` };
}
/** A connection name stays taken after deletion, so a draft reusing one could never be approved.
 * Connection names are listed to every installation; credential names are not, so a setup's credential
 * name is only checked on approval, where the answer goes to the Owner. */
async function assertConnectionNameFree(env: Bindings, owner: string, name: string) {
  assert(
    !(await env.DB.prepare('SELECT 1 FROM connections WHERE owner_id=? AND name=?').bind(owner, name).first()),
    'name_taken',
    409,
    `A connection named "${name}" exists or existed. Choose another name and submit again.`,
  );
}
/** Checks each connection of a setup as the Owner's form would and runs its tests on its draft policy;
 * an error names the connection by index and name. The stored draft has the origins and rules as
 * approval will save them, so the Owner reviews exactly that. */
async function setupRequest(env: Bindings, owner: string, setup: z.infer<typeof setupInput>) {
  const failed: string[] = [];
  const connections = [];
  for (const [i, c] of setup.connections.entries()) {
    const at = `connections.${i} "${c.name}"`;
    let origin, policy;
    try {
      ({ origin } = targetUrl(c.origin, '/', env.ALLOW_LOCAL_HTTP === 'true'));
      policy = JSON.parse(policyJson(c, env.ALLOW_LOCAL_HTTP === 'true')) as Required<ConnectionPolicy>;
    } catch (e) {
      const { code, status, message } = e as Fault;
      throw new Fault(code, status, `${at}: ${message}`);
    }
    await assertConnectionNameFree(env, owner, c.name);
    failed.push(...mismatches(policy, c.tests, `${at} tests`));
    const { deny, approval, free } = policy;
    connections.push({ ...c, origin, deny, approval, free });
  }
  assertTests(
    failed,
    setup.connections.reduce((n, c) => n + c.tests.length, 0),
  );
  return { setup: { ...setup, connections } };
}
/** Checks an update applied to its connection as the Owner's form would, and runs its tests on the
 * proposed policy and, for the Owner's comparison, on the current one. */
async function updateRequest(env: Bindings, owner: string, update: z.infer<typeof updateInput>) {
  const { conn, policy: current } = await activeConnection(env, owner, update.connection);
  const merged = withChanges(conn, update.changes);
  const policy = JSON.parse(policyJson(merged, env.ALLOW_LOCAL_HTTP === 'true')) as Required<ConnectionPolicy>;
  if (merged.name !== conn.name) await assertConnectionNameFree(env, owner, merged.name);
  assertTests(mismatches(policy, update.tests), update.tests.length);
  // Changed rules are stored normalized, so the Owner compares them with the saved ones line by line.
  const proposed: Record<string, unknown> = { name: merged.name, description: merged.description, ...policy };
  return {
    update: {
      ...update,
      changes: Object.fromEntries(Object.keys(update.changes).map((k) => [k, proposed[k]])) as typeof update.changes,
    },
    current: verdicts(current, update.tests).map((d) => d.code),
    updatedAt: conn.updated_at,
  };
}
export async function accessStatus(env: Bindings, p: Principal, rid: string) {
  assert(p.scopes.includes('access:request'), 'insufficient_scope', 403);
  const row = await env.DB.prepare(
    "SELECT id,status,expires_at,fingerprint,consumed_at,json_extract(requested_json,'$.ids') AS ids,json_extract(requested_json,'$.grants') AS grants FROM access_requests WHERE id=? AND client_id=?",
  )
    .bind(rid, p.clientId)
    .first<{
      id: string;
      status: string;
      expires_at: number;
      fingerprint: string | null;
      consumed_at: number | null;
      ids: string | null;
      grants: string | null;
    }>();
  assert(
    row,
    'request_not_found',
    404,
    'This installation has no access request with this id, or the request is more than about 25 hours old and has been archived. Use the id access.request returned; to ask again, call access.request.',
  );
  // An approved invocation runs once before expires_at; an approved grant request stays approved.
  const status =
    row.status === 'approved' && row.fingerprint
      ? row.consumed_at
        ? 'executed'
        : row.expires_at < now()
          ? 'expired'
          : 'approved'
      : row.status === 'pending' && row.expires_at < now()
        ? 'expired'
        : row.status;
  // An approved setup names what it created, so the Agent can go on to use the connections.
  const created: Partial<NonNullable<StoredRequest['ids']>> =
    row.status === 'approved' && row.ids ? JSON.parse(row.ids) : {};
  // expires_at is the decision deadline while pending and the run deadline of an approved invocation.
  const deadline =
    row.status === 'pending' || (row.status === 'approved' && row.fingerprint) ? { expires_at: row.expires_at } : {};
  return {
    id: row.id,
    status,
    ...deadline,
    ...created,
    ...(row.status === 'approved' && row.grants
      ? { grants: await standingGrants(env, p, JSON.parse(row.grants)) }
      : {}),
  };
}
/** The requested grants as they stand now, not as approved: a re-grant only lengthens a grant, so it may
 * outlast the Owner's choice, while each extension keeps its own expiry. A grant that ended is left out. */
async function standingGrants(env: Bindings, p: Principal, requested: z.infer<typeof grantInput>[]) {
  const live = await env.DB.prepare(
    "SELECT resource_type,resource_id,permission,expires_at,extensions_json FROM grants WHERE owner_id=? AND client_id=? AND status='active' AND (expires_at IS NULL OR expires_at>?)",
  )
    .bind(p.userId, p.clientId, now())
    .all<{
      resource_type: string;
      resource_id: string;
      permission: string;
      expires_at: number | null;
      extensions_json: string | null;
    }>();
  return live.results
    .filter((g) =>
      requested.some(
        (r) => r.resourceType === g.resource_type && r.resourceId === g.resource_id && r.permission === g.permission,
      ),
    )
    .map(({ extensions_json, ...g }) => ({ ...g, extensions: liveExtensions(extensions_json) }));
}
const connectionNotFound =
  'No active connection has this id; check credentials.list. If the API is not configured, tell the user which connection is needed: its origin, how it authenticates, and suggested allowed paths, methods and rules. If the user agrees, submit it as a draft with access.request requested.setup (credential field names only, with a test table); never submit one without asking.';
async function activeConnection(env: Bindings, owner: string, cid: string) {
  const conn = await env.DB.prepare(
    "SELECT name,origin,description,auth_json,policy_json,updated_at FROM connections WHERE id=? AND owner_id=? AND status='active'",
  )
    .bind(cid, owner)
    .first<ConnectionRow>();
  assert(conn, 'connection_not_found', 404, connectionNotFound);
  return { conn, policy: JSON.parse(conn.policy_json) as ConnectionPolicy };
}
/** The origin a request names when it is not the connection's own, as URL writes it; undefined when it
 * names none or the connection's. It passes the checks a connection's origin passes, and the connection
 * has to list its host or reach any host: refused otherwise, on submission and again when the request
 * runs, so an approval ends with the entry it relied on. */
function otherOrigin(env: Bindings, conn: ConnectionRow, policy: ConnectionPolicy, origin: string | undefined) {
  if (origin === undefined) return undefined;
  const url = targetUrl(origin, '/', env.ALLOW_LOCAL_HTTP === 'true');
  if (url.origin === new URL(conn.origin).origin) return undefined;
  assert(
    policy.anyHost || matchHost(policy.hosts, url.hostname),
    'host_not_allowed',
    403,
    `This connection does not list ${url.hostname} among its extra hosts (hosts in its policy_json), so its credential cannot go to ${url.origin}. Tell the user which host is needed and why; the Owner can add it to the connection’s extra hosts on the connections page. Do not retry with another spelling of the address.`,
  );
  return url.origin;
}
const nextStep =
  'In reason name the target the way a person knows it (name, account, creation date), how you identified an opaque id, and the expected effect, so the Owner can check it.';
/** The refusal for a decision other than run, with the next step in its hint; elsewhere when the
 * request names another origin than the connection's own. */
function refusal(d: Decision, elsewhere = false) {
  if (d.code === 'path_denied')
    return new Fault(
      'path_denied',
      403,
      `The connection rule "deny ${d.rule}" forbids this request. No grant or approval can lift it; only the Owner can, by editing the connection. Do not request access: tell the user which rule blocked the request.`,
    );
  const outside = d.code === 'path_not_allowed' ? 'path' : d.code === 'method_not_allowed' ? 'method' : null;
  return new Fault(
    d.code,
    403,
    d.code === 'approval_required'
      ? `This request needs a one-time Owner approval even with a grant. Call access.request with requested.invocation set to this exact request, wait until access.status is approved, then resend it unchanged. ${elsewhere ? 'It goes to another origin than the connection’s own, where no grant, extension or free rule counts: the request for approval and the resend must carry the same origin. ' : ''}${nextStep}`
      : outside
        ? `This ${outside} is outside the connection’s regular scope; that is not a prohibition. For a single operation call access.request with requested.invocation set to this exact request. For multi-step work request a grant for this connection whose ${outside === 'path' ? 'paths (and methods if needed)' : 'methods (and paths if needed)'} cover it as a temporary scope extension. ${nextStep}`
        : `No grant covers this request. Call access.request with requested.grants for multi-step work, or with requested.invocation set to this exact request for a single operation; after approval resend it unchanged. ${nextStep}`,
  );
}
const hex = (data: ArrayBuffer) => Buffer.from(data).toString('hex');
const sha256 = async (data: Uint8Array<ArrayBuffer>) => hex(await crypto.subtle.digest('SHA-256', data));
/** Binds a one-time approval to what reaches upstream from the caller: connection, method, the path
 * exactly as sent (so two encodings of one route need two approvals), sorted query, the forwarded
 * caller headers (lowercase and sorted by Headers) and the body. A request to another origin than the
 * connection's own adds that origin, so its approval runs nowhere else, the connection's origin
 * included, and an approval without one runs only there. */
async function requestFingerprint(
  connection: string,
  method: string,
  path: string,
  query: [string, string][],
  headers: Headers,
  body: Uint8Array<ArrayBuffer>,
  origin?: string,
) {
  const sortedQuery = query.map((pair) => JSON.stringify(pair)).sort();
  return sha256(
    new TextEncoder().encode(
      JSON.stringify([
        connection,
        method,
        path,
        sortedQuery,
        [...headers],
        await sha256(body),
        ...(origin ? [origin] : []),
      ]),
    ),
  );
}
/** Atomically consumes one live approval of this exact request, returning its request id. */
async function consumeApproval(env: Bindings, p: Principal, fingerprint: string) {
  const row = await env.DB.prepare(
    "UPDATE access_requests SET consumed_at=? WHERE id=(SELECT id FROM access_requests WHERE owner_id=? AND client_id=? AND fingerprint=? AND status='approved' AND consumed_at IS NULL AND expires_at>? LIMIT 1) AND consumed_at IS NULL RETURNING id",
  )
    .bind(now(), p.userId, p.clientId, fingerprint, now())
    .first<{ id: string }>();
  return row?.id;
}
export async function parseProxyRequest(request: Request, connection: string): Promise<InvokeRequest> {
  const url = new URL(request.url),
    prefix = `/v1/proxy/${resourceId.parse(connection)}`;
  assert(url.pathname.startsWith(prefix + '/'), 'invalid_path');
  const input = invokeInput.parse({
    connection,
    path: url.pathname.slice(prefix.length),
    method: request.method,
    headers: Object.fromEntries(request.headers),
  });
  return {
    ...input,
    query: [...url.searchParams],
    body: ['GET', 'HEAD'].includes(input.method)
      ? undefined
      : await boundedBytes(request.body).catch((e) => {
          throw e instanceof Fault && e.code === 'body_too_large' ? bodyTooLarge() : e;
        }),
  };
}
const bodyTooLarge = () =>
  new Fault(
    'body_too_large',
    413,
    'A request body is limited to 1 MiB. Split the work into smaller requests; upload large files with the host’s own tools.',
  );
export async function invoke(env: Bindings, p: Principal, input: InvokeRequest) {
  const requestBody =
    input.body === undefined
      ? undefined
      : typeof input.body === 'string'
        ? new TextEncoder().encode(input.body)
        : new Uint8Array(input.body);
  if ((requestBody?.byteLength ?? 0) > 1024 * 1024) throw bodyTooLarge();
  assert(!['GET', 'HEAD'].includes(input.method) || !requestBody?.byteLength, 'body_not_allowed');
  assert(p.scopes.includes('connection:invoke'), 'insufficient_scope', 403);
  const { conn, policy } = await activeConnection(env, p.userId, input.connection);
  const origin = otherOrigin(env, conn, policy, input.origin);
  const grant = await liveGrant(env, p, 'connection', input.connection, 'connection:invoke');
  const decided = decide(policy, input.method, input.path, grant && liveExtensions(grant.extensions_json));
  if (decided.code === 'path_denied') throw refusal(decided);
  // The policy speaks for the connection's own origin. On another one a deny rule still refuses, and
  // nothing but a one-time approval of this request, origin included, runs it.
  const decision: Decision = origin ? { code: 'approval_required' } : decided;
  const url = targetUrl(origin ?? conn.origin, input.path, env.ALLOW_LOCAL_HTTP === 'true');
  const query = Array.isArray(input.query) ? input.query : Object.entries(input.query ?? {});
  appendQuery(url, query);
  const headers = upstreamHeaders(input.headers ?? {});
  // A matching one-time approval runs any request the policy refuses but does not deny.
  if (decision.code !== 'run') {
    const approval = await consumeApproval(
      env,
      p,
      await requestFingerprint(
        input.connection,
        input.method,
        input.path,
        query,
        headers,
        requestBody ?? new Uint8Array(),
        origin,
      ),
    );
    if (!approval) throw refusal(decision, !!origin);
    await audit(env, p.clientId, 'access:consume', approval);
  }
  const auth = authInput.parse(JSON.parse(conn.auth_json));
  if (auth.type !== 'none') {
    const values = (await boundSecret(env, p.userId, auth.secretId)).values;
    validateAuthBinding(auth, values);
    if (auth.type === 'basic') {
      const encoded = Buffer.from(`${values[auth.usernameField]}:${values[auth.passwordField]}`, 'utf8').toString(
        'base64',
      );
      headers.set('authorization', `Basic ${encoded}`);
    } else if (auth.type === 'query') {
      // A caller must not shadow an injected key through duplicate or
      // case-insensitive upstream query parsing.
      for (const name of [...url.searchParams.keys()])
        if (name.toLowerCase() === auth.name.toLowerCase()) url.searchParams.delete(name);
      url.searchParams.set(auth.name, values[auth.field]);
      assert(url.href.length <= 32768, 'query_too_large', 413, QUERY_TOO_LARGE);
    } else {
      headers.set(
        auth.type === 'bearer' ? 'authorization' : auth.name,
        auth.type === 'bearer' ? `Bearer ${values[auth.field]}` : values[auth.field],
      );
    }
  }
  await audit(env, p.clientId, 'connection:invoke', input.connection, 'started');
  let response: Response;
  // Only a failed request has an unknown outcome. The timeout also aborts a long response stream.
  try {
    response = await fetch(url, {
      method: input.method,
      headers,
      body: ['GET', 'HEAD'].includes(input.method)
        ? undefined
        : typeof input.body === 'string'
          ? input.body
          : requestBody,
      redirect: 'manual',
      signal: AbortSignal.timeout(20000),
    });
  } catch {
    await audit(env, p.clientId, 'connection:invoke', input.connection, 'outcome_unknown');
    throw new Fault(
      'upstream_outcome_unknown',
      502,
      'The upstream may or may not have run this request, and a one-time approval it used is spent. Read the upstream state first and decide from that; never retry a write automatically.',
    );
  }
  const safeHeaders = new Headers();
  for (const key of ['content-type', 'content-length', 'retry-after', 'etag', 'last-modified']) {
    const value = response.headers.get(key);
    if (value) safeHeaders.set(key, value);
  }
  safeHeaders.set('cache-control', 'no-store');
  await audit(env, p.clientId, 'connection:invoke', input.connection, `http_${response.status}`);
  return { status: response.status, headers: Object.fromEntries(safeHeaders), body: response.body };
}
