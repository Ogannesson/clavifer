// The console's own logic that runs without a page: reading credential files, telling which connections
// wait for authorization, reading the state again, the connection form's fields, and the presets.
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  awaitingAuthorization,
  inOrder,
  keyText,
  replaced,
  type ConnectionAuth,
  type Secret,
} from '../apps/web/src/api';
import { authToForm, formToAuth } from '../apps/web/src/auth-form';
import { placeholders, PRESETS } from '../apps/web/src/presets';
import {
  asValue,
  flattenJson,
  isDer,
  isPkcs12,
  jsonFields,
  unescapedKey,
  unsupportedText,
} from '../apps/web/src/values';
import { authEndpoints, authInput } from '../apps/worker/src/vault';
import type { Auth } from '../packages/core/auth';
import { jwtKey } from '../packages/core/jwt';
import { targetUrl } from '../packages/core/proxy';
import { base64Bytes, encodeElement, privateKeyPem } from '../packages/core/pem';
import { encryptedKey, UnsupportedKeyEncryption } from '../packages/core/pkcs8';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/keys/${name}`, import.meta.url));
// A throwaway key under a passphrase, written by Node's OpenSSL with the cipher named.
const encrypted = (cipher: string, passphrase: string) =>
  generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher, passphrase },
  }).privateKey;

describe('a pasted or loaded value', () => {
  it('is one line without the line break after it', () => {
    expect(asValue('abc\n')).toBe('abc');
    expect(asValue('abc\r\n')).toBe('abc');
    expect(asValue('abc')).toBe('abc');
  });
  it('keeps several lines exactly as they are', () => {
    expect(asValue('a\nb\n')).toBe('a\nb\n');
    expect(asValue('a\n\n')).toBe('a\n\n');
  });
});

const pem = generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
}).privateKey;
describe('a private key pasted as a JSON file writes it', () => {
  it('gets its line breaks back', () => {
    // The value of private_key in a service account's key file, as copied from between the quotes or
    // with them.
    expect(unescapedKey(JSON.stringify(pem).slice(1, -1))).toBe(pem);
    expect(unescapedKey(JSON.stringify(pem))).toBe(pem);
    expect(
      unescapedKey(String.raw`-----BEGIN RSA PRIVATE KEY-----\r\nAB\/C\u003d\r\n-----END RSA PRIVATE KEY-----\n`),
    ).toBe('-----BEGIN RSA PRIVATE KEY-----\r\nAB/C=\r\n-----END RSA PRIVATE KEY-----\n');
  });
  it('leaves any other text alone', () => {
    // Already in lines, or one line without escapes (the service reads its body as base64 still).
    expect(unescapedKey(pem)).toBeUndefined();
    expect(unescapedKey(pem.replace(/\n/g, ' '))).toBeUndefined();
    // Escapes, but no private key, or a block that is not one.
    expect(unescapedKey(String.raw`D:\keys\new.pem`)).toBeUndefined();
    expect(unescapedKey(String.raw`-----BEGIN CERTIFICATE-----\nAB\n-----END CERTIFICATE-----`)).toBeUndefined();
    // Not a JSON string: an escape JSON does not have, or more of the file than one string.
    expect(unescapedKey(String.raw`-----BEGIN PRIVATE KEY-----\xAB\n-----END PRIVATE KEY-----`)).toBeUndefined();
    expect(unescapedKey(`"private_key": ${JSON.stringify(pem)}`)).toBeUndefined();
    expect(unescapedKey(`${JSON.stringify(pem)},`)).toBeUndefined();
  });
});

describe('a key the service cannot read', () => {
  it('names the field and the reason', () => {
    expect(keyText('The key in field "private_key" is a PEM whose body is not base64.')).toMatch(
      /^字段「private_key」里的密钥是 PEM，但正文不是 base64。/,
    );
    expect(keyText('The key in field "k" is not valid hex.')).toBe('字段「k」里的密钥按所选的密钥编码 hex 解不开。');
    expect(keyText('The key in field "k" is not a private key for ES256.')).toBe(
      '字段「k」里的密钥不是 ES256 能用的私钥，密钥类型和所选算法不配。',
    );
    expect(keyText('The key in field "k" is a PEM "DSA PRIVATE KEY", which is not a format this service reads.')).toBe(
      '字段「k」里的密钥是 PEM「DSA PRIVATE KEY」，本服务读不了这种格式。',
    );
  });
  it('has a text for every reason jwt.ts gives', async () => {
    const reasons: unknown[] = [];
    const refuse = (...args: Parameters<typeof jwtKey>) => jwtKey(...args).catch((e) => reasons.push(e.message));
    const rsa = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    }).privateKey;
    await refuse('HS256', '%', 'k', 'base64');
    await refuse('HS256', '', 'k', 'hex');
    await refuse('ES256', 'abc', 'k');
    await refuse('ES256', encrypted('aes-256-cbc', 'p'), 'k');
    await refuse('ES256', JSON.stringify(pem).slice(1, -1), 'k');
    await refuse('ES256', '-----BEGIN EC PRIVATE KEY-----\nMAA=\n-----END EC PRIVATE KEY-----', 'k');
    await refuse('ES256', '-----BEGIN DSA PRIVATE KEY-----\nMAA=\n-----END DSA PRIVATE KEY-----', 'k');
    await refuse('ES256', '{', 'k');
    await refuse('ES256', rsa, 'k');
    expect(reasons).toHaveLength(9);
    for (const reason of reasons) expect(keyText(reason), String(reason)).toMatch(/^字段「k」里的密钥/);
  });
  it('keeps the generic text for a hint of another shape', () => {
    expect(keyText(undefined)).toBeUndefined();
    expect(keyText('The key in field "k" is something new.')).toBeUndefined();
  });
});

describe('reading the state again', () => {
  // Each load waits until the test answers it, so answers can arrive in any order.
  const loads = () => {
    const answers: ((value: number | null) => void)[] = [];
    const applied: (number | null)[] = [];
    const ordered = inOrder<number | null>((v) => applied.push(v));
    const load = () => ordered(() => new Promise<number | null>((resolve) => answers.push(resolve)));
    return { ordered, load, answers, applied };
  };
  it('drops an answer to a read that started before the one applied last', async () => {
    const { load, answers, applied } = loads();
    // A poll starts, then an action's own refresh, whose answer arrives first.
    const poll = load();
    const refresh = load();
    answers[1](2);
    expect(await refresh).toBe(2);
    answers[0](1);
    expect(await poll).toBe(1);
    expect(applied).toEqual([2]);
  });
  it('applies answers that arrive in order, and one started after the last applied', async () => {
    const { load, answers, applied } = loads();
    const first = load();
    const second = load();
    answers[0](1);
    answers[1](2);
    await Promise.all([first, second]);
    const third = load();
    answers[2](3);
    await third;
    expect(applied).toEqual([1, 2, 3]);
  });
  it('keeps a sign-out from being undone by a poll that started before it', async () => {
    const { ordered, load, answers, applied } = loads();
    const poll = load();
    await ordered(async () => null);
    answers[0](1);
    await poll;
    expect(applied).toEqual([null]);
  });
});

describe('a new console', () => {
  const page = (script: string) =>
    `<!doctype html><html><head><script type="module" crossorigin src="${script}"></script></head><body><div id="app"></div></body></html>`;
  it('is there when / no longer loads the script this page runs', () => {
    expect(replaced(page('/assets/index-B2.js'), '/assets/index-A1.js')).toBe(true);
    expect(replaced(page('/assets/index-A1.js'), '/assets/index-A1.js')).toBe(false);
  });
});

describe('reading a JSON file as fields', () => {
  it('takes every string at any depth under its own key, and a passphrase apart', () => {
    // The shape of Box's configuration file.
    const box = {
      boxAppSettings: {
        clientID: 'id',
        clientSecret: 'secret',
        appAuth: { publicKeyID: 'kid', privateKey: '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n', passphrase: 'p' },
      },
      enterpriseID: '123',
    };
    expect(flattenJson(JSON.stringify(box))).toEqual({
      fields: {
        clientID: 'id',
        clientSecret: 'secret',
        publicKeyID: 'kid',
        privateKey: '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n',
        enterpriseID: '123',
      },
      skipped: [],
      conflicts: [],
      invalid: [],
      passphrases: ['p'],
    });
  });
  it('keeps the line breaks of a key that JSON escapes', () => {
    const google =
      '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nAB\\nCD\\n-----END PRIVATE KEY-----\\n"}';
    expect(flattenJson(google)!.fields.private_key).toBe(
      '-----BEGIN PRIVATE KEY-----\nAB\nCD\n-----END PRIVATE KEY-----\n',
    );
  });
  it('lists what it skips, the names it cannot use and the names found twice', () => {
    const found = flattenJson(
      JSON.stringify({
        a: { id: '1', n: 2, ok: true, none: null, list: ['x'] },
        b: { c: { id: '2' } },
        'bad name': 'x',
        '9x': 'y',
      }),
    )!;
    expect(found.skipped).toEqual(['a.n', 'a.ok', 'a.none', 'a.list']);
    expect(found.conflicts).toEqual([['a.id', 'b.c.id']]);
    expect(found.invalid).toEqual(['bad name', '9x']);
    expect(found.fields).toEqual({});
  });
  it('reads only a JSON object', () => {
    for (const text of ['[1]', '"x"', 'null', 'not json', '']) expect(flattenJson(text)).toBeNull();
  });
  it('fills a credential form only when nothing is ambiguous', async () => {
    await expect(jsonFields('[]')).rejects.toThrow('不是 JSON 对象');
    await expect(jsonFields('{"a":{"x":"1"},"b":{"x":"2"}}')).rejects.toThrow('a.x 和 b.x');
    await expect(jsonFields('{"a b":"1"}')).rejects.toThrow('a b');
    const { fields, notice } = await jsonFields('{"token":"t","port":1}');
    expect(fields).toEqual({ token: 't' });
    expect(notice).toContain('port');
  });
  it('fills an approval card with the fields of the draft alone', async () => {
    // A conflict or a bad name outside the draft's fields does not stop it.
    const text = '{"client_id":"i","extra":"e","a":{"dup":"1"},"b":{"dup":"2"},"bad key":"x"}';
    const { fields, notice } = await jsonFields(text, ['client_id', 'client_secret']);
    expect(fields).toEqual({ client_id: 'i' });
    expect(notice).toContain('extra');
    await expect(jsonFields(text, ['dup'])).rejects.toThrow('a.dup 和 b.dup');
  });
  it('opens an encrypted key with the passphrase in the file and keeps neither the passphrase nor the lock', async () => {
    const key = encrypted('aes-256-cbc', 'box-pass');
    const file = JSON.stringify({ boxAppSettings: { appAuth: { privateKey: key, Passphrase: 'box-pass' } } });
    for (const only of [undefined, ['privateKey']]) {
      const { fields, notice } = await jsonFields(file, only);
      expect(Object.keys(fields)).toEqual(['privateKey']);
      expect(privateKeyPem(fields.privateKey)!.label).toBe('PRIVATE KEY');
      expect(notice).toContain('没有保存');
      expect(notice).not.toContain('box-pass');
    }
  });
  it('leaves a key it cannot open as it is, with the passphrase still unsaved', async () => {
    for (const key of [encrypted('aes-256-cbc', 'other'), encrypted('des-ede3-cbc', 'box-pass')]) {
      const { fields, notice } = await jsonFields(JSON.stringify({ privateKey: key, passphrase: 'box-pass' }));
      expect(fields).toEqual({ privateKey: key });
      expect(notice).toContain('privateKey 没能解开');
    }
  });
});

describe('binary files', () => {
  const seq = (...parts: Uint8Array[]) => encodeElement(0x30, ...parts);
  const int = (n: number) => encodeElement(0x02, Uint8Array.of(n));
  const oid = (hex: string) => encodeElement(0x06, Buffer.from(hex, 'hex'));
  // The outline of what `openssl pkcs12 -export` writes (the repository keeps no .p12 file):
  // PFX { version 3, ContentInfo { pkcs7-data, [0] OCTET STRING }, MacData }.
  const pfx = (version: number, contentType: string) =>
    seq(
      int(version),
      seq(oid(contentType), encodeElement(0xa0, encodeElement(0x04, Uint8Array.of(0x30, 0x00)))),
      seq(
        seq(seq(oid('608648016503040201')), encodeElement(0x04, new Uint8Array(32))),
        encodeElement(0x04, new Uint8Array(8)),
        int(1),
      ),
    );
  it('a PKCS#12 bundle is recognized by its content and by its name', () => {
    expect(isPkcs12('upload.bin', pfx(3, '2a864886f70d010701'))).toBe(true);
    expect(isPkcs12('upload.bin', pfx(3, '2a864886f70d010702'))).toBe(true);
    expect(isPkcs12('key.PFX', new Uint8Array(3))).toBe(true);
    expect(isPkcs12('key.p12', new Uint8Array(0))).toBe(true);
  });
  it('a PKCS#12 bundle is not confused with a key or a DER sequence of another kind', () => {
    expect(isPkcs12('key.pem', fixture('p256-pkcs8.pem'))).toBe(false);
    expect(isPkcs12('upload.bin', pfx(1, '2a864886f70d010701'))).toBe(false);
    expect(isPkcs12('upload.bin', pfx(3, '2a864886f70d01050d'))).toBe(false);
    expect(isPkcs12('key.der', seq(int(0)))).toBe(false);
    expect(isPkcs12('key.der', Uint8Array.of(0x30, 0x82, 0xff))).toBe(false);
  });
  it('a DER key is told from a text file', () => {
    for (const name of ['p256-pkcs8.pem', 'rsa-pkcs1.pem', 'ed25519-pkcs8.pem'])
      expect(isDer(base64Bytes(privateKeyPem(fixture(name).toString('utf8'))!.body))).toBe(true);
    expect(isDer(fixture('p256-pkcs8.pem'))).toBe(false);
    expect(isDer(new TextEncoder().encode('{"private_key":"x"}'))).toBe(false);
    expect(isDer(Uint8Array.of(0x30, 0x82, 0xff))).toBe(false);
  });
});

describe('an encrypted key the console cannot decrypt', () => {
  const refusal = (name: string) => {
    try {
      encryptedKey(fixture(`encrypted/${name}`).toString('utf8'));
    } catch (e) {
      return unsupportedText(e as UnsupportedKeyEncryption);
    }
    throw new Error('not refused');
  };
  it('names the algorithm, the conversion and how to drop the passphrase', () => {
    const text = refusal('des-ede3-cbc.pem');
    expect(text).toContain('des-ede3-cbc');
    expect(text).toContain('openssl pkcs8 -topk8 -in in.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 -out out.pem');
    expect(text).toContain('-nocrypt');
  });
  it('converts a traditional PEM key without a passphrase', () => {
    const text = refusal('traditional.pem');
    expect(text).toContain('openssl pkey -in in.pem -out out.pem');
    expect(text).not.toContain('-nocrypt');
  });
});

describe('awaiting authorization', () => {
  const secret = (fields: string[]): Secret => ({
    id: 's1',
    name: 's',
    description: '',
    current_version: 1,
    updated_at: 0,
    fields,
  });
  const refresh = (authorize: boolean): ConnectionAuth => ({
    type: 'oauth-refresh',
    secretId: 's1',
    refreshField: 'refresh_token',
    client: { method: 'none', id: 'app' },
    tokenUrl: 'https://auth.example.com/token',
    ...(authorize ? { authorize: { url: 'https://auth.example.com/authorize' } } : {}),
  });
  it('is a connection authorized in the console whose credential has no refresh token yet', () => {
    expect(awaitingAuthorization(refresh(true), [secret(['client_secret'])])).toBe(true);
    expect(awaitingAuthorization(refresh(true), [])).toBe(true);
    expect(awaitingAuthorization(refresh(true), [secret(['refresh_token'])])).toBe(false);
  });
  it('is never one without authorize, or of another kind', () => {
    expect(awaitingAuthorization(refresh(false), [secret([])])).toBe(false);
    expect(awaitingAuthorization({ type: 'bearer', secretId: 's1', field: 'token' }, [secret([])])).toBe(false);
  });
});

// A value for every placeholder of a preset, as an Owner would write it.
const examples: Record<string, string> = {
  service: 'compute',
  tenant: 'contoso.onmicrosoft.com',
  thumbprint: 'q3YJ4fbwXH2u5gJb0yjmEkVv6r0rL5H0bNlWqTqJ7nA',
  domain: 'example.okta.com',
  shop: 'example',
  account_id: 'AbC123',
  mydomain: 'example',
  server: 'na3',
  key_id: 'ABC1234567',
  issuer_id: '57246542-96fe-1a63-e053-0824d011072a',
  site: 'blog.example.com',
  project: 'example',
  scope: 'gmail.readonly',
};
const filled = (value: unknown) =>
  JSON.parse(JSON.stringify(value).replace(/\{([a-z_]+)\}/g, (_, name: string) => examples[name]));

describe('the connection form', () => {
  const ref = ($field: string) => ({ $field });
  const endpoint = 'https://oauth.example.com';
  // Every shape of auth in scripts/fixtures-v2.ts, which wrote the v2 samples.
  const samples: Auth[] = [
    { type: 'none' },
    { type: 'bearer', secretId: 's', field: 'token' },
    { type: 'header', secretId: 's', field: 'token', name: 'X-API-Key' },
    { type: 'basic', secretId: 's', usernameField: 'username', passwordField: 'password' },
    { type: 'query', secretId: 's', field: 'token', name: 'api_key' },
    {
      type: 'jwt',
      secretId: 's',
      jwt: {
        alg: 'RS256',
        keyField: 'private_key',
        header: { kid: ref('key_id'), typ: 'JWT' },
        claims: {
          iss: ref('issuer'),
          aud: 'synthetic-audience',
          video: { room: 'x', roomJoin: true },
          scope: ['a', 'b'],
        },
        lifetime: 1200,
      },
      scheme: '',
    },
    {
      type: 'jwt',
      secretId: 's',
      jwt: {
        alg: 'ES256',
        keyField: 'ec_key',
        claims: { iss: ref('issuer'), aud: 'appstoreconnect-v1' },
        lifetime: 600,
        jti: true,
      },
    },
    {
      type: 'jwt',
      secretId: 's',
      jwt: {
        alg: 'HS256',
        keyField: 'key',
        keyEncoding: 'hex',
        header: { kid: ref('id') },
        claims: { aud: '/admin/' },
        lifetime: 300,
      },
      scheme: 'Ghost',
    },
    {
      type: 'oauth-client',
      secretId: 's',
      client: { method: 'basic', id: ref('client_id'), secretField: 'client_secret' },
      tokenUrl: `${endpoint}/token`,
    },
    {
      type: 'oauth-client',
      secretId: 's',
      client: { method: 'post', id: 'synthetic-literal-client', secretField: 'client_secret' },
      grantType: 'account_credentials',
      params: { account_id: 'synthetic-account' },
      bodyFormat: 'json',
      tokenUrl: `${endpoint}/token`,
    },
    {
      type: 'oauth-client',
      secretId: 's',
      client: {
        method: 'jwt',
        id: ref('client_id'),
        jwt: {
          alg: 'PS256',
          keyField: 'private_key',
          claims: { iss: ref('client_id'), sub: ref('client_id'), aud: `${endpoint}/token` },
          lifetime: 300,
        },
      },
      scope: 'https://graph.example.com/.default',
      tokenUrl: `${endpoint}/token`,
      header: 'X-Shopify-Access-Token',
      scheme: '',
    },
    {
      type: 'oauth-jwt',
      secretId: 's',
      jwt: {
        alg: 'RS256',
        keyField: 'private_key',
        header: { kid: ref('private_key_id') },
        claims: {
          iss: ref('client_email'),
          scope: 'https://www.googleapis.com/auth/cloud-platform',
          aud: `${endpoint}/token`,
        },
        lifetime: 3600,
      },
      tokenUrl: `${endpoint}/token`,
    },
    {
      type: 'oauth-jwt',
      secretId: 's',
      jwt: {
        alg: 'RS512',
        keyField: 'private_key',
        claims: { iss: ref('client_email'), box_sub_type: 'enterprise', aud: `${endpoint}/no-expiry` },
        lifetime: 60,
        jti: true,
      },
      client: { method: 'post', id: ref('client_email'), secretField: 'client_secret' },
      tokenUrl: `${endpoint}/no-expiry`,
      ttl: 3600,
    },
    {
      type: 'oauth-refresh',
      secretId: 's',
      refreshField: 'refresh_token',
      client: { method: 'post', id: ref('client_id'), secretField: 'client_secret' },
      authorize: {
        url: `${endpoint}/authorize`,
        scope: 'openid https://www.googleapis.com/auth/gmail.readonly',
        params: { access_type: 'offline', prompt: 'consent' },
      },
      tokenUrl: `${endpoint}/token`,
    },
    {
      type: 'oauth-refresh',
      secretId: 's',
      refreshField: 'refresh_token',
      client: { method: 'basic', id: ref('client_id'), secretField: 'client_secret' },
      bodyFormat: 'json',
      tokenUrl: `${endpoint}/no-expiry`,
      ttl: 3600,
    },
    {
      type: 'oauth-refresh',
      secretId: 's',
      refreshField: 'refresh_token',
      client: { method: 'none', id: 'synthetic-public-client' },
      scope: 'read',
      tokenUrl: `${endpoint}/token`,
    },
    {
      type: 'oauth-refresh',
      secretId: 's',
      refreshField: 'refresh_token',
      client: { method: 'basic', id: ref('client_id'), secretField: 'client_secret' },
      authorize: { url: `${endpoint}/authorize` },
      tokenUrl: `${endpoint}/token`,
    },
  ];
  // Members written with the value their absence means, which an unchanged save must keep as written.
  const explicit: Auth[] = [
    {
      type: 'oauth-refresh',
      secretId: 's',
      refreshField: 'refresh_token',
      client: { method: 'none' },
      tokenUrl: `${endpoint}/token`,
    },
    {
      type: 'oauth-client',
      secretId: 's',
      client: { method: 'jwt', jwt: { alg: 'RS256', keyField: 'k', claims: { aud: 'a' }, lifetime: 60, jti: true } },
      tokenUrl: `${endpoint}/token`,
    },
    {
      type: 'oauth-client',
      secretId: 's',
      client: { method: 'jwt', jwt: { alg: 'RS256', keyField: 'k', claims: { aud: 'a' }, lifetime: 60, jti: false } },
      tokenUrl: `${endpoint}/token`,
    },
    {
      type: 'oauth-client',
      secretId: 's',
      client: { method: 'basic', id: 'c', secretField: 'client_secret' },
      bodyFormat: 'form',
      grantType: 'client_credentials',
      params: {},
      tokenUrl: `${endpoint}/token`,
    },
    {
      type: 'jwt',
      secretId: 's',
      jwt: { alg: 'ES256', keyField: 'k', header: {}, claims: {}, lifetime: 60, jti: false },
      header: 'Authorization',
      scheme: 'Bearer',
    },
    {
      type: 'oauth-refresh',
      secretId: 's',
      refreshField: 'refresh_token',
      client: { method: 'jwt', id: ref('client_id'), jwt: { alg: 'ES256', keyField: 'k', claims: {}, lifetime: 60 } },
      authorize: { url: `${endpoint}/authorize`, params: {} },
      tokenUrl: `${endpoint}/token`,
    },
  ];
  // What a browser submits besides: every other text field the form shows, empty.
  const blank = Object.fromEntries(
    [
      'tokenUrl',
      'bodyFormat',
      'params',
      'ttl',
      'grantType',
      'scope',
      'tokenHeader',
      'tokenScheme',
      'jwt.header',
      'client.jwt.header',
      'client.id',
      'authorize.scope',
      'authorize.params',
    ].map((name) => [name, '']),
  );
  for (const [i, auth] of [...samples, ...explicit].entries())
    it(`gives back a stored ${auth.type} auth unchanged (${i + 1})`, () => {
      expect(formToAuth(authToForm(auth))).toEqual(auth);
      expect(formToAuth({ ...blank, ...authToForm(auth) })).toEqual(auth);
    });
  for (const preset of PRESETS)
    it(`gives back the preset ${preset.label} unchanged`, () => {
      const auth = { ...filled(preset.auth), secretId: 's' };
      expect(formToAuth(authToForm(auth))).toEqual(auth);
    });
  it('says what is wrong in what the Owner wrote', () => {
    const form = authToForm(samples[8]);
    expect(() => formToAuth({ ...form, params: 'no equals sign' })).toThrow('名称=值');
    expect(() => formToAuth({ ...authToForm(samples[5]), 'jwt.claims': '[1]' })).toThrow('claims');
    expect(() => formToAuth({ ...form, 'client.idField': '', 'client.id': '' })).toThrow('客户端 ID');
  });
});

describe('presets', () => {
  it('covers every vendor of the design table once', () => {
    expect(new Set(PRESETS.map((p) => p.id)).size).toBe(PRESETS.length);
    expect(PRESETS.length).toBe(29);
  });
  for (const preset of PRESETS)
    it(`${preset.label} is exactly what the server's auth schema takes once its placeholders are filled`, () => {
      for (const name of placeholders([preset.origin, preset.auth])) expect(examples).toHaveProperty(name);
      const written = { ...filled(preset.auth), secretId: 'sec_1' };
      // A misspelt member would be dropped by the schema rather than refused, so nothing may be dropped.
      const auth = authInput.parse(written);
      expect(auth).toEqual(written);
      expect(() => authEndpoints(auth, false)).not.toThrow();
      expect(() => targetUrl(filled(preset.origin), '/')).not.toThrow();
      expect(preset.source.length).toBeGreaterThan(0);
      for (const url of preset.source) expect(url).toMatch(/^https:\/\//);
      expect(preset.checked).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });
});
