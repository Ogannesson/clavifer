// How a connection authenticates, as its auth_json stores it, and what the Worker, the snapshot and the
// console read from it in common. The schemas that validate it are connectionInput and the draft auth
// in apps/worker/src/vault.ts, built on the parts below that the snapshot shares. The console imports
// this file, so it may not use Node's Buffer.
import { z } from 'zod';
import { assert } from './errors';
import { isRef, type Json, type Jwt, type Ref } from './jwt';
import { hex } from './pem';

/** The name of a field of a secret, as valuesSchema in vault.ts allows it. */
export const authField = z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$/);
/** {"$field": name} stands for the value of that field of the secret. */
export const ref = z.strictObject({ $field: authField });
const isObject = (v: unknown): v is object => typeof v === 'object' && v !== null && !Array.isArray(v);
// A claim nests at most 32 levels, so reading it (the recipe of a cached token) never runs out of stack.
const shallow = (v: unknown, depth = 0): boolean =>
  typeof v !== 'object' || v === null || (depth < 32 && Object.values(v).every((x) => shallow(x, depth + 1)));
/** A JWT claim: any JSON value (what arrives is parsed JSON, so it is one) or a field of the secret; an
 * object with a $field key is only ever the latter. */
export const claim = z
  .union([ref, z.custom<Json>()])
  .refine((v) => !(isObject(v) && Object.hasOwn(v, '$field')) || ref.safeParse(v).success, {
    message: '{"$field": name} names one field of the secret and has no other key',
  })
  .refine((v) => shallow(v), { message: 'a claim nests at most 32 levels deep' });

/** Where the credential goes: header (Authorization by default) and the scheme before it ("Bearer" by
 * default; "" for none). */
export type Present = { header?: string; scheme?: string };
/** How a client proves which client it is to a token endpoint (RFC 6749 §2.3.1, RFC 7523 §2.2). */
export type Client =
  | { method: 'basic' | 'post'; id: string | Ref; secretField: string }
  | { method: 'jwt'; id?: string | Ref; jwt: Jwt }
  | { method: 'none'; id?: string | Ref };
/** A token endpoint and how to ask it; ttl stands in for an expires_in the response lacks. */
export type Exchange = Present & {
  tokenUrl: string;
  bodyFormat?: 'form' | 'json';
  params?: Record<string, string>;
  ttl?: number;
};
export type Authorize = { url: string; scope?: string; params?: Record<string, string> };
export type Auth =
  | { type: 'none' }
  | { type: 'bearer'; secretId: string; field: string }
  | { type: 'header'; secretId: string; field: string; name: string }
  | { type: 'basic'; secretId: string; usernameField: string; passwordField: string }
  | { type: 'query'; secretId: string; field: string; name: string }
  | ({ type: 'jwt'; secretId: string; jwt: Jwt } & Present)
  | ({
      type: 'oauth-client';
      secretId: string;
      client: Exclude<Client, { method: 'none' }>;
      grantType?: string;
      scope?: string;
    } & Exchange)
  | ({
      type: 'oauth-jwt';
      secretId: string;
      jwt: Jwt;
      client?: Extract<Client, { method: 'basic' | 'post' }>;
    } & Exchange)
  | ({
      type: 'oauth-refresh';
      secretId: string;
      refreshField: string;
      client: Client;
      scope?: string;
      authorize?: Authorize;
    } & Exchange);
type Without<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
/** An auth as a setup draft writes it: the secret it names is the one the setup creates. */
export type DraftAuth = Without<Auth, 'secretId'>;
/** The kinds that trade the secret for a token at a token endpoint. */
export type ExchangeAuth = Extract<Auth, { type: 'oauth-client' | 'oauth-jwt' | 'oauth-refresh' }>;
export const exchanges = (auth: Auth): auth is ExchangeAuth =>
  auth.type === 'oauth-client' || auth.type === 'oauth-jwt' || auth.type === 'oauth-refresh';

const refs = (entries: Record<string, unknown> | undefined) =>
  Object.values(entries ?? {}).flatMap((v) => (isRef(v) ? [v.$field] : []));
const jwtFields = (jwt: Jwt) => [jwt.keyField, ...refs(jwt.header), ...refs(jwt.claims)];
const clientFields = (client: Client | undefined) => [
  ...(client && isRef(client.id) ? [client.id.$field] : []),
  ...(client?.method === 'basic' || client?.method === 'post' ? [client.secretField] : []),
  ...(client?.method === 'jwt' ? jwtFields(client.jwt) : []),
];
/** Every field of its secret the auth reads, each once. */
export function authFields(auth: DraftAuth): string[] {
  const fields =
    auth.type === 'none'
      ? []
      : auth.type === 'basic'
        ? [auth.usernameField, auth.passwordField]
        : auth.type === 'jwt'
          ? jwtFields(auth.jwt)
          : auth.type === 'oauth-client'
            ? clientFields(auth.client)
            : auth.type === 'oauth-jwt'
              ? [...jwtFields(auth.jwt), ...clientFields(auth.client)]
              : auth.type === 'oauth-refresh'
                ? [auth.refreshField, ...clientFields(auth.client)]
                : [auth.field];
  return [...new Set(fields)];
}
/** Whether the Owner authorizes the auth in the console, which writes its refresh token. */
export const authorizes = <T extends DraftAuth>(
  auth: T,
): auth is Extract<T, { type: 'oauth-refresh' }> & { authorize: Authorize } =>
  auth.type === 'oauth-refresh' && !!auth.authorize;
/** The fields its secret must hold for the auth to be stored: those authFields names, but the refresh
 * token of a connection the Owner authorizes in the console, which the secret gets only then. */
export const requiredFields = (auth: DraftAuth) =>
  authorizes(auth) ? [...new Set(clientFields(auth.client))] : authFields(auth);
/** Refuses values that lack a field the auth needs (see requiredFields). */
export function assertFields(auth: DraftAuth, values: Record<string, string>) {
  for (const field of requiredFields(auth))
    assert(
      Object.hasOwn(values, field) && typeof values[field] === 'string' && values[field].length > 0,
      'secret_field_not_found',
      404,
    );
}
// JSON with the keys of every object in order, so equal configurations read alike however written.
const canonical = (value: unknown): unknown =>
  Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((k) => [k, canonical((value as Record<string, unknown>)[k])]),
        )
      : value;
/** What decides which token an exchange gets, as the hex SHA-256 of its canonical JSON: the auth without
 * the secret it names, where the token goes and how to authorize it. Connections whose recipes are
 * equal share one cached token. */
export async function recipe(auth: ExchangeAuth) {
  const { secretId, header, scheme, ...rest } = auth;
  const { authorize, ...exchange } = rest as typeof rest & { authorize?: Authorize };
  const json = new TextEncoder().encode(JSON.stringify(canonical(exchange)));
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', json)));
}
