import { afterEach, describe, expect, it, vi } from 'vitest';
import { encryptSecret, parseRootKeys } from '../packages/core/crypto';
import { appendQuery, credentialHeaderName, upstreamHeaders } from '../packages/core/proxy';
import { authInput, invoke, invokeInput, parseProxyRequest, validateAuthBinding } from '../apps/worker/src/vault';
import { type Bindings, type Principal, boundedBytes } from '../apps/worker/src/context';

const principal: Principal = { userId: 'owner', clientId: 'client', scopes: ['connection:invoke'] };
const basic = authInput.parse({
  type: 'basic',
  secretId: 'secret',
  usernameField: 'username',
  passwordField: 'password',
});
const query = authInput.parse({ type: 'query', secretId: 'secret', field: 'token', name: 'api_key' });
const noAuth = authInput.parse({ type: 'none' });
afterEach(() => vi.unstubAllGlobals());

// Exercise the actual vault, envelope decryption, grant gate, and network
// boundary while keeping the test independent from D1 and external services.
async function fixture(auth: ReturnType<typeof authInput.parse>, values: Record<string, string> = {}, allowed = true) {
  const rootKey = `1:${Buffer.from('p'.repeat(32)).toString('base64url')}`;
  const envelope = await encryptSecret(
    parseRootKeys(rootKey),
    { ownerId: 'owner', secretId: 'secret', version: 1 },
    values,
  );
  const events: string[] = [];
  const env = {
    ROOT_KEY: rootKey,
    ALLOW_LOCAL_HTTP: 'false',
    DB: {
      prepare(sql: string) {
        let args: unknown[] = [];
        const statement = {
          bind(...values: unknown[]) {
            args = values;
            return statement;
          },
          async first() {
            if (sql.includes('FROM grants')) return allowed ? { allowed: 1 } : null;
            if (sql.includes('UPDATE access_requests')) return null;
            if (sql.includes('FROM connections'))
              return {
                origin: 'https://api.example.com',
                auth_json: JSON.stringify(auth),
                policy_json: JSON.stringify({ paths: ['/v1'], methods: ['GET', 'HEAD', 'POST'] }),
              };
            if (sql.includes('FROM secrets')) return { current_version: 1, envelope_json: JSON.stringify(envelope) };
            if (sql.includes('FROM system_state')) return { value: 'owner' };
            throw new Error('Unexpected fixture query');
          },
          async run() {
            if (sql.includes('INSERT INTO audit_events')) events.push(String(args[5]));
            return { meta: { changes: 1 } };
          },
        };
        return statement;
      },
    },
  } as unknown as Bindings;
  return { env, events };
}

describe('HTTP authentication and policy boundaries', () => {
  it('injects UTF-8 Basic authentication and strips caller credential and method override headers', async () => {
    const { env } = await fixture(basic, { username: 'synthetic-user', password: 'pässword-for-tests' });
    const upstream = vi.fn(async (_url: URL, init: RequestInit) => {
      const headers = new Headers(init.headers);
      expect(Buffer.from(headers.get('authorization')!.slice(6), 'base64').toString('utf8')).toBe(
        'synthetic-user:pässword-for-tests',
      );
      expect(headers.get('cookie')).toBeNull();
      expect(headers.get('x-http-method-override')).toBeNull();
      expect(headers.get('content-type')).toBe('application/octet-stream');
      expect(init.redirect).toBe('manual');
      expect(init.signal).toBeInstanceOf(AbortSignal);
      return new Response('accepted');
    });
    vi.stubGlobal('fetch', upstream);
    await invoke(
      env,
      principal,
      invokeInput.parse({
        connection: 'connection',
        path: '/v1/upload',
        method: 'POST',
        headers: {
          Authorization: 'Bearer caller-only',
          Cookie: 'caller-cookie',
          'X-HTTP-Method-Override': 'DELETE',
          'Content-Type': 'application/octet-stream',
        },
        body: 'request',
      }),
    );
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('injects one query credential, removes shadow values, and preserves repeated noncredential parameters', async () => {
    const token = 'synthetic /?+=&秘密';
    const { env } = await fixture(query, { token });
    const upstream = vi.fn(async (url: URL) => {
      expect(url.origin).toBe('https://api.example.com');
      expect(url.searchParams.getAll('api_key')).toEqual([token]);
      expect(url.searchParams.has('API_KEY')).toBe(false);
      expect(url.searchParams.getAll('tag')).toEqual(['first', 'second']);
      return new Response('accepted');
    });
    vi.stubGlobal('fetch', upstream);
    const input = await parseProxyRequest(
      new Request(
        'https://vault.example.com/v1/proxy/connection/v1/items?api_key=forged&API_KEY=shadow&tag=first&api_key=duplicate&tag=second',
      ),
      'connection',
    );
    await invoke(env, principal, input);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['username missing', { password: 'synthetic-pass' }],
    ['colon in username', { username: 'user:other', password: 'synthetic-pass' }],
    ['control in username', { username: 'user\n', password: 'synthetic-pass' }],
    ['control in password', { username: 'synthetic-user', password: 'synthetic\rpass' }],
  ])('rejects invalid Basic fields before making a network request: %s', async (_label, values) => {
    const { env } = await fixture(basic, values);
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);
    await expect(
      invoke(env, principal, invokeInput.parse({ connection: 'connection', path: '/v1' })),
    ).rejects.toThrow();
    expect(upstream).not.toHaveBeenCalled();
  });

  it('requires own bound properties, including when a field names an inherited property', () => {
    const auth = authInput.parse({ type: 'bearer', secretId: 'secret', field: 'constructor' });
    expect(() => validateAuthBinding(auth, {})).toThrow('secret_field_not_found');
  });

  it.each([' synthetic-token', 'synthetic-token ', 'synthetic\r\ntoken', 'synthetic\0token', 'synthetic-tökén'])(
    'rejects header credentials that would be rejected or silently transformed by Headers: %j',
    async (token) => {
      const auth = authInput.parse({ type: 'header', secretId: 'secret', field: 'token', name: 'X-API-Key' });
      const { env } = await fixture(auth, { token });
      const upstream = vi.fn();
      vi.stubGlobal('fetch', upstream);
      await expect(
        invoke(env, principal, invokeInput.parse({ connection: 'connection', path: '/v1' })),
      ).rejects.toMatchObject({ code: 'invalid_header_credential' });
      expect(upstream).not.toHaveBeenCalled();
    },
  );

  it.each([
    'Host',
    'Keep-Alive',
    'X-Original-URL',
    'X-Original-URI',
    'X-Rewrite-URL',
    'X-HTTP-Method-Override',
    'X-Method-Override',
    'TE',
    'Forwarded',
    'Origin',
    'Referer',
    'CF-Access-Client-Secret',
  ])('does not allow credential injection into a control header %s', (name) => {
    expect(credentialHeaderName(name)).toBe(false);
    expect(authInput.safeParse({ type: 'header', secretId: 'secret', field: 'token', name }).success).toBe(false);
  });

  it('removes headers nominated by Connection and preserves normal API headers', () => {
    const headers = upstreamHeaders({
      Connection: 'keep-alive, X-Remove-Me, invalid token',
      'Keep-Alive': 'timeout=5',
      'X-Remove-Me': 'private',
      Accept: 'application/json',
      'X-API-Version': '2026',
    });
    expect(Object.fromEntries(headers)).toEqual({ accept: 'application/json', 'x-api-version': '2026' });
    expect(credentialHeaderName('Authorization')).toBe(true);
    expect(credentialHeaderName('X-API-Key')).toBe(true);
  });

  it.each(['api key', 'api_key[]', 'api&key', 'api=key', 'api\nkey'])(
    'requires an explicit unambiguous credential parameter name: %s',
    (name) => {
      expect(authInput.safeParse({ type: 'query', secretId: 'secret', field: 'token', name }).success).toBe(false);
    },
  );

  it('rejects excessive queries and does not allow a query to change the origin', () => {
    const url = new URL('https://api.example.com/v1');
    appendQuery(url, [
      ['redirect', 'https://other.example/admin#frag'],
      ['tag', 'a&api_key=forged'],
    ]);
    expect(url.origin).toBe('https://api.example.com');
    expect(url.hash).toBe('');
    expect(url.searchParams.get('tag')).toBe('a&api_key=forged');
    expect(() =>
      appendQuery(
        new URL('https://api.example.com/v1'),
        Array.from({ length: 101 }, () => ['tag', 'x'] as [string, string]),
      ),
    ).toThrow(expect.objectContaining({ code: 'invalid_query' }));
    expect(() =>
      appendQuery(new URL('https://api.example.com/v1'), [
        ['first', '秘'.repeat(3000)],
        ['second', '密'.repeat(3000)],
      ]),
    ).toThrow(expect.objectContaining({ code: 'query_too_large', message: expect.stringContaining('paginate') }));
    for (const [name, value] of [
      ['name', 'foo\naccount.id=mine'],
      ['name', 'a' + String.fromCharCode(0x202e) + 'b'],
      ['na' + String.fromCharCode(0x200b) + 'me', 'x'],
    ])
      expect(() => appendQuery(new URL('https://api.example.com/v1'), [[name, value]])).toThrow(
        expect.objectContaining({ code: 'invalid_query' }),
      );
    appendQuery(new URL('https://api.example.com/v1'), [['q', 'two words, 中文']]);
  });

  it('checks the installation grant before decrypting or contacting upstream', async () => {
    const { env } = await fixture(basic, { username: 'synthetic-user', password: 'synthetic-pass' }, false);
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);
    await expect(
      invoke(env, principal, invokeInput.parse({ connection: 'connection', path: '/v1' })),
    ).rejects.toMatchObject({ code: 'grant_required', status: 403 });
    expect(upstream).not.toHaveBeenCalled();
  });
});

describe('raw HTTP forwarding and outcome semantics', () => {
  it('preserves the text content type default for MCP callers', async () => {
    const { env } = await fixture(noAuth);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: URL, init: RequestInit) => {
        const request = new Request(url, init);
        expect(request.headers.get('content-type')).toBe('text/plain;charset=UTF-8');
        expect(await request.text()).toBe('synthetic UTF-8 文本');
        return new Response('accepted');
      }),
    );
    await invoke(
      env,
      principal,
      invokeInput.parse({ connection: 'connection', path: '/v1', method: 'POST', body: 'synthetic UTF-8 文本' }),
    );
  });

  it('returns an empty HEAD body while preserving response metadata', async () => {
    const { env } = await fixture(noAuth);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: URL, init: RequestInit) => {
        expect(init.method).toBe('HEAD');
        expect(init.body).toBeUndefined();
        return new Response(null, {
          headers: { 'content-type': 'application/octet-stream', etag: '"synthetic-etag"' },
        });
      }),
    );
    const response = await invoke(
      env,
      principal,
      invokeInput.parse({ connection: 'connection', path: '/v1', method: 'HEAD' }),
    );
    expect(response.body).toBeNull();
    expect(response.headers.etag).toBe('"synthetic-etag"');
  });

  it('preserves non-UTF-8 request and response bytes and repeated path segments', async () => {
    const bytes = new Uint8Array([0, 255, 128, 195, 40, 10, 0]);
    const { env } = await fixture(noAuth);
    const upstream = vi.fn(async (url: URL, init: RequestInit) => {
      expect(url.pathname).toBe('/v1/proxy/connection/upload');
      expect(new Uint8Array(await new Response(init.body).arrayBuffer())).toEqual(bytes);
      return new Response(bytes, {
        headers: { 'content-type': 'application/octet-stream', 'set-cookie': 'not-returned' },
      });
    });
    vi.stubGlobal('fetch', upstream);
    const input = await parseProxyRequest(
      new Request('https://vault.example.com/v1/proxy/connection/v1/proxy/connection/upload', {
        method: 'POST',
        body: bytes,
        headers: { 'content-type': 'application/octet-stream' },
      }),
      'connection',
    );
    const response = await invoke(env, principal, input);
    expect(new Uint8Array(await new Response(response.body).arrayBuffer())).toEqual(bytes);
    expect(response.headers).toEqual({ 'cache-control': 'no-store', 'content-type': 'application/octet-stream' });
  });

  it('bounds both raw REST bytes and UTF-8 MCP bytes before a network request', async () => {
    const { env } = await fixture(noAuth);
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);
    await expect(
      parseProxyRequest(
        new Request('https://vault.example.com/v1/proxy/connection/v1', {
          method: 'POST',
          body: new Uint8Array(1024 * 1024 + 1),
        }),
        'connection',
      ),
    ).rejects.toMatchObject({ code: 'body_too_large', status: 413 });
    await expect(
      invoke(
        env,
        principal,
        invokeInput.parse({ connection: 'connection', path: '/v1', method: 'POST', body: 'é'.repeat(600000) }),
      ),
    ).rejects.toMatchObject({ code: 'body_too_large', status: 413 });
    expect(upstream).not.toHaveBeenCalled();
  });

  it('streams a response larger than the MCP text bound and records the upstream status', async () => {
    const { env, events } = await fixture(noAuth);
    const chunk = new Uint8Array(64 * 1024);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        let sent = 0;
        return new Response(
          new ReadableStream<Uint8Array>({
            pull(controller) {
              sent += chunk.byteLength;
              controller.enqueue(chunk);
              if (sent >= 2 * 1024 * 1024) controller.close();
            },
          }),
        );
      }),
    );
    const response = await invoke(env, principal, invokeInput.parse({ connection: 'connection', path: '/v1' }));
    expect((await new Response(response.body).arrayBuffer()).byteLength).toBe(2 * 1024 * 1024);
    expect(events).toEqual(['started', 'http_200']);
    const bounded = await fixture(noAuth);
    const second = await invoke(bounded.env, principal, invokeInput.parse({ connection: 'connection', path: '/v1' }));
    await expect(boundedBytes(second.body)).rejects.toMatchObject({ code: 'body_too_large' });
    expect(bounded.events).toEqual(['started', 'http_200']);
  });

  it('does not silently discard a caller-supplied GET body', async () => {
    const { env } = await fixture(noAuth);
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);
    await expect(
      invoke(env, principal, invokeInput.parse({ connection: 'connection', path: '/v1', body: 'write' })),
    ).rejects.toMatchObject({ code: 'body_not_allowed' });
    expect(upstream).not.toHaveBeenCalled();
  });

  it('never retries an upstream write when the response is lost', async () => {
    const { env, events } = await fixture(noAuth);
    const upstream = vi.fn(async () => {
      throw new Error('upstream disconnected');
    });
    vi.stubGlobal('fetch', upstream);
    await expect(
      invoke(
        env,
        principal,
        invokeInput.parse({ connection: 'connection', path: '/v1', method: 'POST', body: 'write' }),
      ),
    ).rejects.toMatchObject({ code: 'upstream_outcome_unknown', status: 502 });
    expect(upstream).toHaveBeenCalledTimes(1);
    expect(events).toEqual(['started', 'outcome_unknown']);
  });

  it('returns redirects without following them or exposing Location', async () => {
    const { env } = await fixture(noAuth);
    const upstream = vi.fn(async (_url: URL, init: RequestInit) => {
      expect(init.redirect).toBe('manual');
      return new Response(null, { status: 302, headers: { location: 'https://127.0.0.1/private' } });
    });
    vi.stubGlobal('fetch', upstream);
    const response = await invoke(env, principal, invokeInput.parse({ connection: 'connection', path: '/v1' }));
    expect(response.status).toBe(302);
    expect(response.headers.location).toBeUndefined();
    expect(upstream).toHaveBeenCalledTimes(1);
  });
});
