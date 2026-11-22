// A connection's auth and the connection form's fields, both ways. The form is uncontrolled: authToForm
// gives each field the value it starts with, formToAuth reads what the form submits. A stored auth goes
// through both unchanged, every member it holds kept and none added, including a member written with the
// value its absence means (bodyFormat "form", header "Authorization", a client assertion's jti): such a
// member is part of a cached token's recipe, so dropping it would cost a token exchange, and it is the
// Owner's or a draft's to remove. What the form cannot show as a field travels in a hidden one.
import type { Auth, Authorize, Client, DraftAuth, Exchange, Present } from '../../../packages/core/auth';
import { isRef, type Jwt, type JwtAlg, type KeyEncoding } from '../../../packages/core/jwt';

/** The form's fields by name; a checkbox holds "on" when ticked and is absent otherwise. */
export type FormValues = Record<string, string>;
/** An auth the form starts from: a stored one, a preset's (without a secret) or none. */
type Seed = Partial<
  Present &
    Exchange & {
      type: string;
      secretId: string;
      field: string;
      name: string;
      usernameField: string;
      passwordField: string;
      jwt: Jwt;
      client: Client;
      grantType: string;
      scope: string;
      refreshField: string;
      authorize: Authorize;
    }
>;

const json = (value: unknown) => JSON.stringify(value, null, 2);
const lines = (params: Record<string, string>) =>
  Object.entries(params)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
// Fields left out of the result stand for members the auth does not have.
const defined = (entries: [string, string | undefined][]): FormValues =>
  Object.fromEntries(entries.filter((e): e is [string, string] => e[1] !== undefined));
/** Extra parameters as lines of name=value; an empty object, which the lines cannot tell from none, is
 * marked in a hidden field. */
const paramFields = (name: string, params: Record<string, string> | undefined): [string, string | undefined][] => [
  [name, params && lines(params)],
  [`${name}.empty`, params && !Object.keys(params).length ? 'on' : undefined],
];
/** prefix is "jwt." for the auth's own JWT and "client.jwt." for a client assertion, whose jti the form
 * does not offer (an assertion always carries one) and so keeps hidden as stored. */
function jwtFields(prefix: string, jwt: Jwt, assertion: boolean): [string, string | undefined][] {
  return [
    [prefix + 'alg', jwt.alg],
    [prefix + 'keyField', jwt.keyField],
    [prefix + 'keyEncoding', jwt.keyEncoding],
    [prefix + 'header', jwt.header && json(jwt.header)],
    [prefix + 'claims', json(jwt.claims)],
    [prefix + 'lifetime', String(jwt.lifetime)],
    // The checkbox: ticked for true; false, which it cannot show, is marked apart.
    [prefix + 'jti', assertion ? jwt.jti?.toString() : jwt.jti ? 'true' : undefined],
    [prefix + 'jtiFalse', !assertion && jwt.jti === false ? 'on' : undefined],
  ];
}
export function authToForm(auth: Seed | DraftAuth | Auth | null): FormValues {
  const a = (auth ?? {}) as Seed;
  const client = a.client;
  return defined([
    ['type', a.type],
    ['secretId', a.secretId],
    ['field', a.field],
    ['headerName', a.name],
    ['usernameField', a.usernameField],
    ['passwordField', a.passwordField],
    ...(a.jwt ? jwtFields('jwt.', a.jwt, false) : []),
    ['tokenUrl', a.tokenUrl],
    ['bodyFormat', a.bodyFormat],
    ...paramFields('params', a.params),
    ['ttl', a.ttl?.toString()],
    ['tokenHeader', a.header],
    ['tokenScheme', a.scheme || undefined],
    ['noScheme', a.scheme === '' ? 'on' : undefined],
    ['client.method', client?.method],
    // A client is shown with where its id comes from, even when it has none.
    ['client.idField', client && (isRef(client.id) ? client.id.$field : '')],
    ['client.id', client && typeof client.id === 'string' ? client.id : undefined],
    ['client.secretField', client && 'secretField' in client ? client.secretField : undefined],
    ...(client?.method === 'jwt' ? jwtFields('client.jwt.', client.jwt, true) : []),
    ['grantType', a.grantType],
    ['scope', a.scope],
    ['refreshField', a.refreshField],
    ['authorizing', a.authorize ? 'on' : undefined],
    ['authorize.url', a.authorize?.url],
    ['authorize.scope', a.authorize?.scope],
    ...paramFields('authorize.params', a.authorize?.params),
  ]);
}

/** Thrown for what the Owner wrote wrong in the form, in words the console shows as they are. */
const wrong = (text: string) => new Error(text);
function readParams(form: FormValues, name: string, label: string) {
  const entries = (form[name] ?? '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const at = line.indexOf('=');
      if (at < 1) throw wrong(`「${label}」每行写成「名称=值」，例如 audience=https://api.example.com。`);
      return [line.slice(0, at).trim(), line.slice(at + 1).trim()];
    });
  return entries.length || form[`${name}.empty`] ? Object.fromEntries(entries) : undefined;
}
function jsonObject(text: string, label: string) {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    value = null;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw wrong(`「${label}」要写成一个 JSON 对象，例如 {"aud": "https://api.example.com"}。`);
  return value as Record<string, never>;
}
const text = (form: FormValues, name: string) => (form[name] ?? '').trim();
/** Present only when written: an empty field is a member the auth does not have. */
const optional = <K extends string>(key: K, value: string) => (value ? ({ [key]: value } as Record<K, string>) : {});
function readJwt(form: FormValues, prefix: string): Jwt {
  const alg = text(form, prefix + 'alg') as JwtAlg;
  const header = text(form, prefix + 'header');
  const jti = form[prefix + 'jti'];
  return {
    alg,
    keyField: text(form, prefix + 'keyField'),
    ...(alg.startsWith('HS') ? { keyEncoding: text(form, prefix + 'keyEncoding') as KeyEncoding } : {}),
    ...(header ? { header: jsonObject(header, 'JWT header') } : {}),
    claims: jsonObject(form[prefix + 'claims'] ?? '', 'claims'),
    lifetime: Number(form[prefix + 'lifetime']),
    ...(jti === 'true' ? { jti: true } : jti === 'false' || form[prefix + 'jtiFalse'] ? { jti: false } : {}),
  };
}
function readClient(form: FormValues): Client | undefined {
  const method = text(form, 'client.method');
  if (!method) return undefined;
  const idField = text(form, 'client.idField');
  const literal = text(form, 'client.id');
  const id = idField ? { $field: idField } : literal || undefined;
  if (method === 'basic' || method === 'post') {
    if (!id) throw wrong('这种客户端认证要填写客户端 ID，或选择存放它的凭据字段。');
    return { method, id, secretField: text(form, 'client.secretField') };
  }
  const named = id ? { id } : {};
  return method === 'jwt' ? { method, ...named, jwt: readJwt(form, 'client.jwt.') } : { method: 'none', ...named };
}
/** The auth the form describes, as the connection routes take it. Throws, in Chinese, what to fix. */
export function formToAuth(form: FormValues): Auth {
  const type = text(form, 'type');
  const secretId = text(form, 'secretId');
  if (type === 'none' || !type) return { type: 'none' };
  if (type === 'basic')
    return {
      type,
      secretId,
      usernameField: text(form, 'usernameField'),
      passwordField: text(form, 'passwordField'),
    };
  if (type === 'bearer') return { type, secretId, field: text(form, 'field') };
  if (type === 'header' || type === 'query')
    return { type, secretId, field: text(form, 'field'), name: text(form, 'headerName') };
  const scheme = form.noScheme ? { scheme: '' } : optional('scheme', text(form, 'tokenScheme'));
  const present = { ...optional('header', text(form, 'tokenHeader')), ...scheme };
  if (type === 'jwt') return { type, secretId, jwt: readJwt(form, 'jwt.'), ...present };
  const params = readParams(form, 'params', '额外参数');
  const bodyFormat = text(form, 'bodyFormat') as '' | 'form' | 'json';
  const ttl = text(form, 'ttl');
  const exchange = {
    tokenUrl: text(form, 'tokenUrl'),
    ...(bodyFormat ? { bodyFormat } : {}),
    ...(params ? { params } : {}),
    ...(ttl ? { ttl: Number(ttl) } : {}),
    ...present,
  };
  const client = readClient(form);
  const scope = optional('scope', text(form, 'scope'));
  if (type === 'oauth-client')
    return {
      type,
      secretId,
      client: client as Exclude<Client, { method: 'none' }>,
      ...optional('grantType', text(form, 'grantType')),
      ...scope,
      ...exchange,
    };
  if (type === 'oauth-jwt')
    return {
      type,
      secretId,
      jwt: readJwt(form, 'jwt.'),
      ...(client ? { client: client as Extract<Client, { method: 'basic' | 'post' }> } : {}),
      ...exchange,
    };
  const authorizeParams = readParams(form, 'authorize.params', '授权参数');
  return {
    type: 'oauth-refresh',
    secretId,
    refreshField: text(form, 'refreshField'),
    client: client!,
    ...scope,
    ...(form.authorizing
      ? {
          authorize: {
            url: text(form, 'authorize.url'),
            ...optional('scope', text(form, 'authorize.scope')),
            ...(authorizeParams ? { params: authorizeParams } : {}),
          },
        }
      : {}),
    ...exchange,
  };
}
