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
 * one segment "a/b" or, after decoding, as the two segments "a" and "b"; policy reads the decoded
 * form, and deny and approval rules the raw one as well (see matchRule). Decoding only splits a
 * segment, it never joins two or drops one, so whatever the upstream resolves, the decoded path spells
 * the same segments joined by "/". A deny or approval rule without wildcards that names a resource
 * therefore still matches every request reaching it; it can also match a key that merely contains
 * "/", which refuses more, never less. A wildcard counts segments, so for it the raw reading, which
 * keeps "a/b" one segment, is needed too. The only ways a path could join or
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
/** A connection's token or authorization endpoint, which receives a credential or the Owner's browser:
 * an origin as targetUrl takes one, with a path (an Entra tenant is in it) but without a query, a
 * fragment or a user name. Returned as URL writes it. */
export function endpointUrl(text: string, allowHttp = false) {
  const url = new URL(text);
  assert(!url.search && !url.hash && !url.username && !url.password, 'endpoint_must_not_contain_query');
  return targetUrl(url.origin, url.pathname, allowHttp).href;
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
// One segment of a rule: a literal, a segment {name} with a literal prefix and suffix around it, or
// ANY for any number of segments, none included.
type RuleSegment = string | { prefix: string; suffix: string } | typeof ANY;
const ANY = Symbol('**');
// A connection rule is "METHOD /path": the method is one of METHODS or *. In the path "{name}" stands
// for any characters within one segment, with at most one per segment and a literal before and after
// it if wanted ("{r}:setIamPolicy", "v{n}"); the name is only a note. "**" as a whole segment stands
// for any number of segments, and a trailing /* is the older spelling of a trailing /**. Every other
// "*", "{" or "}" makes the rule invalid; written percent-encoded (%2A, %7B, %7D) they are literal.
// Deny, approval and free rules share this form. A rule saved as a bare path takes implicitMethod
// (GET for free rules, * for the others).
export function parseRule(text: string, implicitMethod?: string) {
  const parts = text.trim().split(/\s+/);
  assert(text.length <= 320 && (parts.length === 2 || (parts.length === 1 && implicitMethod)), 'invalid_rule');
  const method = parts.length === 2 ? parts[0].toUpperCase() : implicitMethod!;
  const raw = parts[parts.length - 1];
  assert(method === '*' || (METHODS as readonly string[]).includes(method), 'invalid_rule');
  const prefix = raw.endsWith('/*');
  const path = prefix ? raw.slice(0, -2) || '/' : raw;
  const written = path.split('/').slice(1);
  assert(
    path.startsWith('/') && written.every((s) => s === '**' || /^[^*{}]*(\{\w*\}[^*{}]*)?$/.test(s)),
    'invalid_rule',
  );
  // The path is checked as a request path would be, with each wildcard standing in as a letter that
  // cannot complete a percent-encoding.
  try {
    canonicalPath(path.replace(/\{\w*\}|\*\*/g, 'x'));
  } catch {
    throw new Fault('invalid_rule');
  }
  // A literal is compared decoded, so an encoded slash in it splits it as it splits a request path.
  const segments: RuleSegment[] = written.flatMap((s): RuleSegment[] => {
    if (s === '**') return [ANY];
    const hole = /\{\w*\}/.exec(s);
    if (!hole) return fold(decodeURIComponent(s)).split('/');
    const [before, after] = [s.slice(0, hole.index), s.slice(hole.index + hole[0].length)].map((v) =>
      fold(decodeURIComponent(v)),
    );
    assert(!before.includes('/') && !after.includes('/'), 'invalid_rule');
    return [{ prefix: before, suffix: after }];
  });
  // One trailing slash is ignored, as it is on a request.
  if (segments.at(-1) === '') segments.pop();
  if (prefix) segments.push(ANY);
  // Whether the rule uses the wildcards of this syntax; the older trailing /* does not count.
  const wildcard = written.some((s) => s === '**' || s.includes('{'));
  return { text: `${method} ${raw}`, method, segments, wildcard };
}
// Only ASCII letters fold: full Unicode lowercasing maps the Kelvin sign U+212A to "k", which would
// let a path the upstream treats as different satisfy a rule.
const fold = (text: string) => text.replace(/[A-Z]/g, (c) => c.toLowerCase());
const unslash = (path: string) => path.replace(/(.)\/$/, '$1');
// The decoded reading of a canonical path: decoded as a whole, then split at every "/".
const decodedSegments = (path: string) => (path === '/' ? [] : fold(unslash(path)).slice(1).split('/'));
// The raw reading: split at each "/" as written, then each segment decoded, so "a%2Fb" stays one segment.
const rawSegments = (raw: string) => {
  const path = unslash(raw);
  return path === '/'
    ? []
    : path
        .slice(1)
        .split('/')
        .map((s) => fold(decodeURIComponent(s)));
};
const segmentMatches = (rule: Exclude<RuleSegment, typeof ANY>, segment: string) =>
  typeof rule === 'string'
    ? rule === segment
    : segment.length >= rule.prefix.length + rule.suffix.length &&
      segment.startsWith(rule.prefix) &&
      segment.endsWith(rule.suffix);
// Wildcard matching with two pointers: on a mismatch it returns to the last ** and lets it take one
// more segment. Each step moves the path pointer forward or the rule pointer back to that **, so the
// work is bounded by the product of the two lengths; no regular expression is built from a rule.
function segmentsMatch(rule: RuleSegment[], path: string[]) {
  let r = 0,
    p = 0,
    any = -1,
    taken = 0;
  while (p < path.length) {
    const s = rule[r];
    if (s === ANY) {
      any = r++;
      taken = p;
    } else if (s !== undefined && segmentMatches(s, path[p])) {
      r++;
      p++;
    } else if (any >= 0) {
      r = any + 1;
      p = ++taken;
    } else return false;
  }
  while (rule[r] === ANY) r++;
  return r === rule.length;
}
/** True when a rule covers this request. path is already canonical and is read decoded; raw, the path
 * as sent, adds the raw reading, where an encoded slash stays inside its segment (GitLab's
 * "group%2Fproject" is one id). A wildcard counts segments, and an upstream may read either way:
 * deny and approval rules match when either reading does, so neither steps around them; free rules
 * pass all, under which a rule with {name} or ** matches only when both readings do, so it runs
 * nothing an upstream routes elsewhere. A rule without them matches the raw reading only where it
 * matches the decoded one, so it reads decoded as it always did. ASCII case and one trailing slash
 * are ignored so a rule cannot be sidestepped by spelling the same route differently. A GET rule also
 * covers HEAD, which upstreams answer with the same handler. */
export function matchRule(rules: string[] | undefined, method: string, path: string, raw?: string, all = false) {
  const readings = [decodedSegments(path), ...(raw && /%2f/i.test(raw) ? [rawSegments(raw)] : [])];
  return (rules ?? []).some((text) => {
    const rule = parseRule(text);
    if (rule.method !== '*' && rule.method !== method && !(rule.method === 'GET' && method === 'HEAD')) return false;
    const matches = (segments: string[]) => segmentsMatch(rule.segments, segments);
    return all && rule.wildcard ? readings.every(matches) : readings.some(matches);
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

// Query parameters that make an upstream run another method or take headers from the query string,
// past the method every rule and the review card read: Google's $httpMethod (also as %24httpMethod),
// the _method of Laravel and Symfony, Salesforce's _HttpMethod and Google's $httpHeaders. They are
// compared decoded and ignoring case, and refused rather than dropped, so an approval shows the real method.
const methodOverride = new Set(['$httpmethod', '_method', '_httpmethod', '$httpheaders']);
// Every caller hands over decoded names: the REST proxy the entries of URLSearchParams, MCP the keys
// as written, which searchParams encodes.
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
    assert(
      !methodOverride.has(name.toLowerCase()),
      'invalid_query',
      400,
      `The query parameter "${name}" makes the upstream rewrite the HTTP method or request headers. Leave it out and send the request with its real method.`,
    );
    url.searchParams.append(name, value);
  }
  assert(url.href.length <= 16384, 'query_too_large', 413, QUERY_TOO_LARGE);
}
export const QUERY_TOO_LARGE =
  'The target URL is limited to 16 KiB (32 KiB with an injected key). Send fewer or shorter query parameters, paginate, or use an endpoint that takes the filter in the request body.';
