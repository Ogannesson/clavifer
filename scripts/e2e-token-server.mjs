import { constants, createHash, generateKeyPairSync, randomBytes, verify } from 'node:crypto';

// A stand-in authorization server for the end-to-end tests, served by a local upstream reached through
// ALLOW_LOCAL_HTTP: a token endpoint per grant, an authorization endpoint, and /whoami, which echoes the
// Authorization the upstream got. Every endpoint counts its calls. Its keys and client credentials are
// generated for each run and stay in this process.
export function tokenServer() {
  const pair = (type, options) =>
    generateKeyPairSync(type, {
      ...options,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
  const rsa = pair('rsa', { modulusLength: 2048 });
  const ec = pair('ec', { namedCurve: 'P-256' });
  const client = {
    id: `e2e-client-${randomBytes(6).toString('hex')}`,
    secret: randomBytes(24).toString('base64url'),
  };
  const issuer = `e2e-${randomBytes(6).toString('hex')}@example.com`;
  const calls = { client: 0, jwt: 0, refresh: 0, code: 0, reused: 0, authorize: 0, whoami: 0 };
  // What the next answers do: a delay before each token answer, the expires_in of each token, whether
  // the code exchange returns a refresh token, a failure of every token endpoint (which then echoes
  // what it was sent), and a refused authorization.
  const settings = { delay: 0, lifetime: 3600, refresh: true, failure: undefined, deny: false };
  // Refresh tokens issued and not used yet; each works once. Codes by value, each also once.
  const live = new Set();
  const codes = new Map();
  // Every access token issued, with the grant it was issued for.
  const issued = new Map();

  const send = (res, status, value, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(JSON.stringify(value));
  };
  const refreshToken = () => {
    const value = `refresh-${randomBytes(12).toString('hex')}`;
    live.add(value);
    return value;
  };
  async function token(res, grant, refresh) {
    await new Promise((done) => setTimeout(done, settings.delay));
    const value = `${grant}-${randomBytes(12).toString('hex')}`;
    issued.set(value, grant);
    send(res, 200, {
      access_token: value,
      token_type: 'Bearer',
      expires_in: settings.lifetime,
      ...(refresh && { refresh_token: refreshToken() }),
    });
  }
  /** The claims of a JWS signed by this server's RSA (RS256, PS256) or EC (ES256) key for aud, else undefined. */
  function verifyJwt(jws, aud) {
    const [h, p, s] = jws.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url'));
    const claims = JSON.parse(Buffer.from(p, 'base64url'));
    const key = {
      RS256: rsa.publicKey,
      PS256: { key: rsa.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
      ES256: { key: ec.publicKey, dsaEncoding: 'ieee-p1363' },
    }[header.alg];
    const now = Date.now() / 1000;
    return key &&
      verify('sha256', Buffer.from(`${h}.${p}`), key, Buffer.from(s, 'base64url')) &&
      claims.aud === aud &&
      claims.iat <= now + 5 &&
      claims.exp > now
      ? { header, claims }
      : undefined;
  }
  async function body(req) {
    let text = '';
    for await (const chunk of req) text += chunk;
    return req.headers['content-type'] === 'application/json'
      ? JSON.parse(text)
      : Object.fromEntries(new URLSearchParams(text));
  }
  // RFC 6749 §2.3.1 form-encodes the id and secret before joining them for Basic.
  const formDecoded = (text) => new URLSearchParams('v=' + text).get('v');
  /** The client a token request authenticates as: by Basic, by the body's client_id and client_secret, or
   * by a client assertion (RFC 7523 §2.2) with a jti; undefined when none of these holds. */
  function authenticated(req, sent, aud) {
    const basic = /^Basic (.+)$/.exec(req.headers.authorization ?? '');
    const [id, secret] = basic
      ? Buffer.from(basic[1], 'base64').toString('utf8').split(':').map(formDecoded)
      : [sent.client_id, sent.client_secret];
    if (id === client.id && secret === client.secret) return client.id;
    if (sent.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') return;
    const assertion = verifyJwt(sent.client_assertion, aud);
    if (assertion?.claims.iss === client.id && assertion.claims.sub === client.id && assertion.claims.jti)
      return client.id;
  }
  // A token endpoint: the grants it takes, each answering for an authenticated request.
  const endpoint = (grants) => async (req, res, url) => {
    const sent = await body(req);
    const aud = `http://${req.headers.host}${url.pathname}`;
    if (settings.failure)
      return send(res, settings.failure.status, {
        error: settings.failure.error,
        error_description: `received ${JSON.stringify(sent)} with ${req.headers.authorization ?? 'no Authorization'}`,
      });
    const grant = grants[sent.grant_type];
    if (!grant) return send(res, 400, { error: 'unsupported_grant_type' });
    if (!grant.public && authenticated(req, sent, aud) !== client.id)
      return send(res, 401, { error: 'invalid_client' });
    return grant.answer(res, sent, aud);
  };
  const s256 = (verifier) => createHash('sha256').update(verifier).digest('base64url');
  const endpoints = {
    '/token/client': endpoint({
      client_credentials: {
        answer: (res) => {
          calls.client++;
          return token(res, 'client');
        },
      },
    }),
    '/token/jwt': endpoint({
      'urn:ietf:params:oauth:grant-type:jwt-bearer': {
        public: true,
        answer: (res, sent, aud) => {
          calls.jwt++;
          const assertion = verifyJwt(sent.assertion, aud);
          if (assertion?.claims.iss !== issuer || !assertion.claims.scope)
            return send(res, 400, { error: 'invalid_grant' });
          return token(res, 'jwt');
        },
      },
    }),
    // One token endpoint for both grants of a user's authorization, as an upstream has.
    '/token/refresh': endpoint({
      refresh_token: {
        answer: (res, sent) => {
          calls.refresh++;
          if (!live.delete(sent.refresh_token)) {
            calls.reused++;
            return send(res, 400, { error: 'invalid_grant' });
          }
          return token(res, 'refresh', true);
        },
      },
      authorization_code: {
        answer: (res, sent) => {
          calls.code++;
          const code = codes.get(sent.code);
          codes.delete(sent.code);
          if (!code || code.redirectUri !== sent.redirect_uri || code.challenge !== s256(sent.code_verifier ?? ''))
            return send(res, 400, { error: 'invalid_grant' });
          return token(res, 'code', settings.refresh);
        },
      },
    }),
    // Consents at once: back to redirect_uri with a code bound to it and to the PKCE challenge, or with
    // access_denied when the authorization is refused.
    '/authorize': async (req, res, url) => {
      calls.authorize++;
      const q = Object.fromEntries(url.searchParams);
      if (
        q.response_type !== 'code' ||
        q.client_id !== client.id ||
        !q.redirect_uri ||
        !q.state ||
        !q.code_challenge ||
        q.code_challenge_method !== 'S256'
      )
        return send(res, 400, { error: 'invalid_request' });
      const back = new URL(q.redirect_uri);
      back.searchParams.set('state', q.state);
      if (settings.deny) back.searchParams.set('error', 'access_denied');
      else {
        const code = randomBytes(16).toString('base64url');
        codes.set(code, { redirectUri: q.redirect_uri, challenge: q.code_challenge });
        back.searchParams.set('code', code);
      }
      res.writeHead(302, { location: back.href });
      res.end();
    },
    '/whoami': async (req, res) => {
      calls.whoami++;
      send(res, 200, { authorization: req.headers.authorization ?? null });
    },
  };
  return {
    client,
    issuer,
    keys: { rsa: rsa.privateKey, ec: ec.privateKey },
    calls,
    settings,
    issued,
    live,
    refreshToken,
    verifyJwt,
    /** Answers req when its path is one of this server's, true then. */
    handle(req, res, url) {
      const answer = endpoints[url.pathname];
      if (!answer) return false;
      answer(req, res, url).catch((e) => send(res, 500, { error: 'server_error', error_description: e.message }));
      return true;
    },
  };
}
