import { isIP } from 'node:net';
import { Fault, assert } from './errors';

const invalidPath = (what: string) =>
  new Fault(
    'invalid_path',
    400,
    `The path ${what}. Do not try another encoding to get around this: use an API that takes the name or key in the request body (such as a bulk endpoint), or ask the user to do it manually.`,
  );
/** Validates a caller path and returns its decoded form, the one every policy decision reads.
 * A semicolon is refused because servlet-style upstreams drop ";param" segments, which would let
 * "/v1/secret;x" reach a route a rule names as "/v1/secret"; control and format characters
 * (bidi overrides, zero-width marks) are refused so a path cannot render differently than it routes.
 *
 * An encoded slash (%2F) and an encoded space (%20) are accepted, because object and key-value
 * stores need them inside a key. The upstream receives the path as sent and reads "a%2Fb" either as
 * one segment "a/b" or, after decoding, as the two segments "a" and "b"; policy always reads the
 * decoded form. Decoding only splits a segment, it never joins two or drops one, so whatever the
 * upstream resolves, the decoded path spells the same segments joined by "/". A deny or approval
 * rule that names a resource therefore still matches every request reaching it; it can also match a
 * key that merely contains "/", which refuses more, never less. The only ways a path could join or
 * drop segments are dot segments, empty segments and ";" parameters, so those stay refused after
 * decoding as well ("a%2F%2Fb", "%2F..%2F", "%2e%2e"). The flip side is that an allowed path, a free
 * rule or a grant extension naming "/x/a" also covers "/x/a%2Fb", the key "a/b", which in a key store
 * sits under "a/". A literal space stays refused: send it as %20. */
export function canonicalPath(path: string) {
  if (!path.startsWith('/')) throw invalidPath('must start with /');
  if (/[\\?#;\x00-\x20]/.test(path))
    throw invalidPath(
      'contains a literal space, ";", "?", "#", "\\" or control character (send a space as %20 and the query string in query)',
    );
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    throw invalidPath('has malformed percent-encoding');
  }
  if (/[%\\?#;\p{Cc}\p{Cf}]/u.test(decoded))
    throw invalidPath('decodes to "%", ";", "?", "#", "\\" or a control or format character');
  if (decoded.includes('//') || decoded.split('/').some((v) => v === '.' || v === '..'))
    throw invalidPath('has an empty, "." or ".." segment, also when spelled with %2F or %2E');
  return decoded;
}
/** True when path lies under one of the prefixes (or no prefixes are given). Both sides are compared
 * decoded, so a prefix and a request may spell the same characters with or without percent-encoding. */
export function checkPath(path: string, prefixes: string[] = []) {
  const decoded = canonicalPath(path);
  return (
    prefixes.length === 0 ||
    prefixes.some((raw) => {
      const prefix = canonicalPath(raw);
      return prefix === '/' || decoded === prefix || decoded.startsWith(prefix.replace(/\/$/, '') + '/');
    })
  );
}
// The hosts a local deployment (development and tests) may reach besides public ones.
const localHost = (host: string) => host === 'localhost' || host === '127.0.0.1';
// An empty label is refused wherever it stands: URL keeps "a..example.com" as written, and it would
// pass for a host below "*.example.com".
const publicHost = (host: string) =>
  !isIP(host) &&
  host.includes('.') &&
  !/(^|\.)(localhost|local|internal|lan|home|test|invalid)$/.test(host) &&
  !host.startsWith('.') &&
  !host.includes('..') &&
  !host.endsWith('.');
export function targetUrl(origin: string, path: string, allowHttp = false) {
  const base = new URL(origin);
  const host = base.hostname.replace(/^\[|\]$/g, '');
  const local = allowHttp && localHost(host);
  assert(base.protocol === 'https:' || (local && base.protocol === 'http:'), 'origin_must_be_https');
  assert(
    base.pathname === '/' && !base.search && !base.hash && !base.username && !base.password,
    'origin_must_not_contain_path',
  );
  assert(local || publicHost(host), 'public_origin_required');
  checkPath(path);
  const result = new URL(path, base);
  assert(result.origin === base.origin, 'invalid_path');
  return result;
}
// An extra host of a connection names where else a one-time approval may send a request: an exact
// hostname ("artifacts.example.com") or "*.suffix" ("*.example.com"), which covers every host below
// the suffix at any depth and never the suffix itself. It is written as URL writes a hostname,
// lowercase ASCII with punycode for an IDN, without scheme, port or path, and is public as an origin
// has to be. A last label that starts with a letter keeps out every spelling of an IP address, and
// two labels after "*." keep out "*.com".
const hostName = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;
export function validHost(text: string, allowLocal = false) {
  const host = text.startsWith('*.') ? text.slice(2) : text;
  return (allowLocal && host === text && localHost(host)) || (hostName.test(host) && publicHost(host));
}
/** The first extra host that covers hostname, which is as URL writes it; a port plays no part. */
export const matchHost = (hosts: string[] | undefined, hostname: string) =>
  (hosts ?? []).find((text) =>
    text.startsWith('*.') ? hostname.endsWith(text.slice(1)) && hostname.length > text.length - 1 : hostname === text,
  );
export const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
// A connection rule is "METHOD /path": the method is one of METHODS or *, the path matches exactly,
// and a trailing /* also covers every path below it. Deny, approval and free rules share this form.
// A rule saved as a bare path takes implicitMethod (GET for free rules, * for the others).
export function parseRule(text: string, implicitMethod?: string) {
  const parts = text.trim().split(/\s+/);
  assert(text.length <= 320 && (parts.length === 2 || (parts.length === 1 && implicitMethod)), 'invalid_rule');
  const method = parts.length === 2 ? parts[0].toUpperCase() : implicitMethod!;
  const raw = parts[parts.length - 1];
  assert(method === '*' || (METHODS as readonly string[]).includes(method), 'invalid_rule');
  const prefix = raw.endsWith('/*');
  const path = prefix ? raw.slice(0, -2) || '/' : raw;
  assert(path.startsWith('/') && !path.includes('*'), 'invalid_rule');
  let decoded: string;
  try {
    decoded = canonicalPath(path);
  } catch {
    throw new Fault('invalid_rule');
  }
  return { text: `${method} ${raw}`, method, path: foldPath(decoded), prefix };
}
// Only ASCII letters fold: full Unicode lowercasing maps the Kelvin sign U+212A to "k", which would
// let a path the upstream treats as different satisfy a rule.
const foldPath = (path: string) => path.replace(/[A-Z]/g, (c) => c.toLowerCase()).replace(/(.)\/$/, '$1');
/** True when a rule covers this request. path is already canonical; ASCII case and one trailing
 * slash are ignored so a rule cannot be sidestepped by spelling the same route differently. A GET
 * rule also covers HEAD, which upstreams answer with the same handler. */
export function matchRule(rules: string[] | undefined, method: string, path: string) {
  const target = foldPath(path);
  return (rules ?? []).some((text) => {
    const rule = parseRule(text);
    if (rule.method !== '*' && rule.method !== method && !(rule.method === 'GET' && method === 'HEAD')) return false;
    return target === rule.path || (rule.prefix && (rule.path === '/' || target.startsWith(rule.path + '/')));
  });
}
// These can alter routing, the method, or the transport independently of the
// connection policy. Authorization is only allowed when the Owner injects it.
const controlHeader =
  /^(authorization|cookie|host|connection|keep-alive|content-length|transfer-encoding|upgrade|te|trailer|expect|forwarded|origin|referer|proxy-.*|sec-.*|cf-.*|x-forwarded-.*|x-real-ip|x-request-id|x-original-(url|uri|host)|x-rewrite-url|x-http-method(-override)?|x-method-override)$/i;
export function credentialHeaderName(name: string) {
  return /^[a-zA-Z0-9-]{1,64}$/.test(name) && (!controlHeader.test(name) || name.toLowerCase() === 'authorization');
}
export function upstreamHeaders(input: HeadersInit) {
  let headers: Headers;
  try {
    headers = new Headers(input);
  } catch {
    throw new Fault('invalid_headers');
  }
  const connectionHeaders = new Set(
    (headers.get('connection') ?? '').split(',').map((name) => name.trim().toLowerCase()),
  );
  for (const name of [...headers.keys()]) {
    if (controlHeader.test(name) || connectionHeaders.has(name)) headers.delete(name);
  }
  return headers;
}

// Control and format characters are refused in values too: a newline inside a value would render as
// a separate parameter on the one-shot review page.
export function appendQuery(url: URL, entries: Iterable<readonly [string, string]>) {
  let count = 0;
  for (const [name, value] of entries) {
    assert(
      ++count <= 100 &&
        name.length > 0 &&
        name.length <= 256 &&
        !/[\x20\p{Cc}\p{Cf}]/u.test(name) &&
        value.length <= 8192 &&
        !/[\p{Cc}\p{Cf}]/u.test(value),
      'invalid_query',
      400,
      'Send at most 100 query parameters; a name is 1-256 characters without spaces or control characters, a value at most 8192 characters without control characters.',
    );
    url.searchParams.append(name, value);
  }
  assert(url.href.length <= 16384, 'query_too_large', 413, QUERY_TOO_LARGE);
}
export const QUERY_TOO_LARGE =
  'The target URL is limited to 16 KiB (32 KiB with an injected key). Send fewer or shorter query parameters, paginate, or use an endpoint that takes the filter in the request body.';
