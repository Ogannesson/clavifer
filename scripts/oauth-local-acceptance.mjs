import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';

// All credentials are synthetic and remain in process. Assertion messages never
// include authorization URLs, codes, cookies, or bearer/refresh token values.
export async function oauthAcceptance({ mf, origin, cookie, db, password }) {
  let passed = 0;
  async function request(
    path,
    { method = 'GET', owner = false, body, form, bearer, expected = 200, headers = {} } = {},
  ) {
    const response = await mf.dispatchFetch(origin + path, {
      method,
      redirect: 'manual',
      headers: {
        'cf-connecting-ip': '127.0.0.2',
        ...(owner ? { origin, cookie } : {}),
        ...(body ? { 'content-type': 'application/json' } : {}),
        ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
        ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
        ...headers,
      },
      body: body ? JSON.stringify(body) : form ? new URLSearchParams(form) : undefined,
    });
    const text = await response.text();
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      value = text;
    }
    assert(
      (Array.isArray(expected) ? expected : [expected]).includes(response.status),
      `OAuth ${method} ${path.split('?')[0]} expected status ${expected}, received ${response.status}; response type=${typeof value}; keys=${typeof value === 'object' ? Object.keys(value).join(',') : ''}`,
    );
    passed++;
    return { response, value };
  }
  const resource = origin + '/v1',
    unconfigured = origin + '/mcp',
    redirectUri = 'https://remote-client.example/oauth/callback';
  const scopes = 'offline_access metadata:list access:request';
  const registration = {
    client_name: 'Remote MCP PKCE test',
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: 'none',
    application_type: 'native',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: scopes,
  };
  const metadata = (await request('/.well-known/oauth-authorization-server/api/auth')).value;
  assert.equal(metadata.issuer, origin + '/api/auth');
  assert(metadata.code_challenge_methods_supported.includes('S256'), 'S256 discovery');
  const protectedMetadata = (await request('/.well-known/oauth-protected-resource/v1')).value;
  assert.equal(protectedMetadata.resource, resource);
  await request('/api/auth/oauth2/register', {
    method: 'POST',
    body: registration,
    headers: { origin },
    expected: 401,
  });
  await request('/api/auth/oauth2/register', {
    method: 'POST',
    body: registration,
    headers: { cookie },
    expected: 403,
  });
  // Dynamic registration is closed, so even the Owner onboards a remote client through administration.
  await request('/api/auth/oauth2/register', { method: 'POST', owner: true, body: registration, expected: 403 });
  const created = (
    await request('/admin/clients', {
      method: 'POST',
      owner: true,
      body: { name: registration.client_name, redirectUris: [redirectUri] },
      expected: 201,
    })
  ).value;
  const clientId = created.clientId;
  assert(clientId, 'Owner creates a remote MCP client');
  const row = await db.prepare('SELECT userId FROM oauthClient WHERE clientId=?').bind(clientId).first();
  const owner = await db.prepare("SELECT value FROM system_state WHERE key='owner_user_id'").first();
  assert.equal(row.userId, owner.value, 'registered client belongs to the Owner');
  const verifier = () => randomBytes(32).toString('base64url');
  function query(proof, changes = {}) {
    return new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scopes,
      resource,
      state: randomBytes(24).toString('base64url'),
      code_challenge: createHash('sha256').update(proof).digest('base64url'),
      code_challenge_method: 'S256',
      ...changes,
    });
  }
  async function authorize(params, owner = true) {
    const { value } = await request('/api/auth/oauth2/authorize?' + params, {
      owner,
      headers: { accept: 'application/json' },
      expected: 200,
    });
    assert.equal(value.redirect, true);
    return new URL(value.url, origin);
  }
  async function consent(url, accept = true) {
    const { value } = await request('/api/auth/oauth2/consent', {
      method: 'POST',
      owner: true,
      body: { accept, oauth_query: url.search.slice(1) },
    });
    assert.equal(value.redirect, true);
    assert.equal(typeof value.url, 'string', 'library returns url');
    return new URL(value.url, origin);
  }
  async function code(changes = {}) {
    const proof = verifier(),
      params = query(proof, { prompt: 'consent', ...changes });
    const review = await authorize(params);
    assert.equal(review.pathname, '/consent');
    const callback = await consent(review);
    assert.equal(callback.origin, new URL(redirectUri).origin);
    assert.equal(callback.searchParams.get('state'), params.get('state'), 'OAuth state preserved');
    assert(callback.searchParams.get('code'), 'authorization code issued');
    return { proof, code: callback.searchParams.get('code') };
  }
  async function exchange(authorization, changes = {}, expected = 200) {
    return request('/api/auth/oauth2/token', {
      method: 'POST',
      form: {
        grant_type: 'authorization_code',
        client_id: clientId,
        redirect_uri: redirectUri,
        code: authorization.code,
        code_verifier: authorization.proof,
        resource,
        ...changes,
      },
      expected,
    });
  }
  async function mcp(
    access,
    method = 'tools/call',
    params = { name: 'credentials.list', arguments: {} },
    expected = 200,
    path = '/v1/mcp',
  ) {
    return request(path, {
      method: 'POST',
      bearer: access,
      headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' },
      body: { jsonrpc: '2.0', id: 1, method, params },
      expected,
    });
  }

  // The unauthenticated browser is redirected to a signed login continuation.
  // After Owner login the page resumes with selected:true, then asks consent.
  const loginProof = verifier(),
    loginParams = query(loginProof),
    login = await authorize(loginParams, false);
  assert.equal(login.pathname, '/login');
  assert(login.searchParams.has('sig'), 'signed OAuth login query');
  const continued = (
    await request('/api/auth/oauth2/continue', {
      method: 'POST',
      owner: true,
      body: { selected: true, oauth_query: login.search.slice(1) },
    })
  ).value;
  assert.equal(continued.redirect, true);
  const review = new URL(continued.url, origin);
  assert.equal(review.pathname, '/consent');
  const unconsented = await authorize(query(verifier()));
  assert.equal(unconsented.pathname, '/consent', 'a signed-in Owner is asked to consent first');
  // Every session so far is the caller's: these make its login older than 10 minutes and recent again.
  const signedIn = (await db.prepare('SELECT createdAt FROM session').first()).createdAt;
  const older = () =>
    db
      .prepare('UPDATE session SET createdAt=?')
      .bind(Date.now() - 700_000)
      .run();
  const recent = () =>
    db
      .prepare('UPDATE session SET createdAt=? WHERE createdAt<?')
      .bind(signedIn, Date.now() - 600_000)
      .run();
  // The query signed for the consent page holds no limit on the login's age, and the library resumes
  // an authorization from any request that carries one and renews the session cookie. An older login
  // sending it that way gets neither a code nor a query signed anew, before the consent or after it.
  const carry = async (oauth_query) => {
    const refused = await request('/api/auth/update-user', {
      method: 'POST',
      owner: true,
      body: { name: 'Test Owner', oauth_query },
      expected: 403,
    });
    assert.deepEqual(Object.keys(refused.value), ['error', 'request_id']);
    assert.equal(refused.value.error, 'oauth_query_not_allowed');
  };
  await older();
  await carry(unconsented.search.slice(1));
  await recent();
  const tampered = new URLSearchParams(review.search);
  tampered.set('resource', unconfigured);
  await request('/api/auth/oauth2/consent', {
    method: 'POST',
    owner: true,
    body: { accept: true, oauth_query: tampered.toString() },
    expected: 400,
  });
  await request('/api/auth/oauth2/consent', {
    method: 'POST',
    owner: true,
    body: { accept: true, scope: 'secret:read', oauth_query: review.search.slice(1) },
    expected: 400,
  });
  const callback = await consent(review);
  assert.equal(callback.searchParams.get('state'), loginParams.get('state'));
  const authorization = { proof: loginProof, code: callback.searchParams.get('code') };
  const issued = (await exchange(authorization)).value;
  assert(issued.access_token && issued.refresh_token, 'access and rotating refresh tokens issued');
  const storedRefresh = await db.prepare('SELECT token FROM oauthRefreshToken WHERE clientId=?').bind(clientId).all();
  assert(
    storedRefresh.results.length > 0 && storedRefresh.results.every((row) => row.token !== issued.refresh_token),
    'refresh tokens are hashed at rest',
  );
  const initialized = (
    await mcp(issued.access_token, 'initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'remote-oauth-test', version: '1' },
    })
  ).value;
  assert.equal(initialized.result.serverInfo.name, 'clavifer');
  const listed = (await mcp(issued.access_token)).value;
  assert(!listed.result.isError, 'remote MCP tool result');
  assert.equal(JSON.parse(listed.result.content[0].text).items.length, 0, 'OAuth consent does not grant secrets');
  const rest = (await request('/v1/secrets', { bearer: issued.access_token })).value;
  assert.equal(rest.items.length, 0, 'one audience serves REST and MCP, and consent grants no resources');

  // With consent on record a login of the last 10 minutes gets a code straight away. An older one is
  // sent to the login page like a visitor who is not signed in, a client cannot ask for a longer
  // limit, and nothing else the older session calls turns a signed query into a code.
  assert((await authorize(query(verifier()))).searchParams.get('code'), 'a recent login gets a code');
  await older();
  const laterProof = verifier(),
    laterParams = query(laterProof);
  for (const params of [laterParams, query(verifier(), { max_age: '86400' })]) {
    const page = await authorize(params);
    assert.equal(page.pathname, '/login', 'a login older than 10 minutes gets no code');
    assert(page.searchParams.has('sig') && !page.searchParams.has('code'));
  }
  const resume = { selected: true, oauth_query: (await authorize(laterParams)).search.slice(1) };
  assert.equal(
    (await request('/api/auth/oauth2/continue', { method: 'POST', owner: true, body: resume, expected: 403 })).value
      .error,
    'recent_login_required',
  );
  await request('/api/auth/oauth2/authorize', {
    method: 'POST',
    owner: true,
    form: Object.fromEntries(laterParams),
    expected: 403,
  });
  // The consent is on record now, so the query signed for the consent page would end in a code.
  await carry(unconsented.search.slice(1));
  await carry(resume.oauth_query);
  // No request outside the steps of an authorization may carry a signed query, in a JSON body or a
  // form, whatever the login's age; none of these reaches its handler, so the password stays.
  const elsewhere = [
    ['/api/auth/get-session', {}],
    ['/api/auth/update-session', {}],
    ['/api/auth/change-password', { currentPassword: password, newPassword: password + '-changed' }],
    ['/api/auth/revoke-other-sessions', {}],
    ['/api/auth/sign-out', {}],
    ['/api/auth/sign-in/social', { provider: 'github' }],
    ['/api/auth/oauth2/public-client-prelogin', { client_id: clientId }],
  ];
  for (const age of [older, recent]) {
    await age();
    for (const [path, fields] of elsewhere)
      for (const kind of ['body', 'form']) {
        const refused = await request(path, {
          method: 'POST',
          owner: true,
          [kind]: { ...fields, oauth_query: resume.oauth_query },
          expected: 403,
        });
        assert.equal(refused.value.error, 'oauth_query_not_allowed', path);
      }
  }
  await older();
  // Signing in again resumes the same request, whether the sign-in carries the query itself or the
  // login page sends it on to /oauth2/continue.
  const again = await request('/api/auth/sign-in/email', {
    method: 'POST',
    body: { email: 'owner@example.com', password, oauth_query: resume.oauth_query },
    headers: { origin },
  });
  cookie = again.response.headers
    .getSetCookie()
    .map((s) => s.split(';')[0])
    .join('; ');
  const sentOn = await request('/api/auth/oauth2/continue', { method: 'POST', owner: true, body: resume });
  for (const { value } of [again, sentOn]) {
    const resumed = new URL(value.url);
    assert.equal(resumed.searchParams.get('state'), laterParams.get('state'));
    await exchange({ proof: laterProof, code: resumed.searchParams.get('code') });
  }
  // The caller's own session, aged above, is recent again for what follows.
  await recent();

  const noPkce = query(verifier());
  noPkce.delete('code_challenge');
  noPkce.delete('code_challenge_method');
  assert.equal((await authorize(noPkce)).searchParams.get('error'), 'invalid_request', 'PKCE required');
  assert.equal(
    (await authorize(query(verifier(), { code_challenge_method: 'plain' }))).searchParams.get('error'),
    'invalid_request',
    'plain PKCE rejected',
  );
  assert.equal(
    (await authorize(query(verifier(), { resource: unconfigured }))).searchParams.get('error'),
    'invalid_target',
    'unknown audience rejected',
  );
  const invalidRedirect = await authorize(query(verifier(), { redirect_uri: 'https://untrusted.example/callback' }));
  assert.equal(invalidRedirect.origin, origin, 'unregistered redirect must never receive codes');
  const deniedParams = query(verifier(), { prompt: 'consent' }),
    denied = await consent(await authorize(deniedParams), false);
  assert.equal(denied.searchParams.get('error'), 'access_denied');
  assert(!denied.searchParams.has('code'));
  assert.equal(denied.searchParams.get('state'), deniedParams.get('state'));
  const wrongVerifier = await code();
  await exchange(wrongVerifier, { code_verifier: verifier() }, 401);
  await exchange(wrongVerifier, {}, 400);
  const wrongResource = await code();
  await exchange(wrongResource, { resource: unconfigured }, 400);
  await exchange(wrongResource, {}, 400);
  await exchange(await code(), { redirect_uri: 'https://remote-client.example/wrong' }, 400);
  const expired = await code();
  await db
    .prepare('UPDATE verification SET expiresAt=? WHERE identifier=?')
    .bind(Date.now() - 1000, createHash('sha256').update(expired.code).digest('base64url'))
    .run();
  await exchange(expired, {}, 400);
  const competing = await code();
  const racingCodes = await Promise.all([exchange(competing, {}, [200, 400]), exchange(competing, {}, [200, 400])]);
  assert.equal(
    racingCodes.filter((result) => result.response.status === 200).length,
    1,
    'concurrent authorization code exchanges issue tokens at most once',
  );
  assert(
    racingCodes
      .filter((result) => result.response.status === 400)
      .every((result) => result.value.error === 'invalid_grant'),
    'competing authorization code exchange is invalid_grant',
  );
  await exchange(authorization, {}, 400);
  // Reusing an authorization code invalidates its issued refresh-token family.
  await request('/api/auth/oauth2/token', {
    method: 'POST',
    form: { grant_type: 'refresh_token', client_id: clientId, refresh_token: issued.refresh_token, resource },
    expected: 400,
  });
  const renewed = (await exchange(await code())).value;
  await request('/api/auth/oauth2/token', {
    method: 'POST',
    form: {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: renewed.refresh_token,
      resource: unconfigured,
    },
    expected: 400,
  });
  const refreshed = (
    await request('/api/auth/oauth2/token', {
      method: 'POST',
      form: { grant_type: 'refresh_token', client_id: clientId, refresh_token: renewed.refresh_token, resource },
    })
  ).value;
  assert(refreshed.refresh_token !== renewed.refresh_token, 'refresh token rotates');
  const replayed = (
    await request('/api/auth/oauth2/token', {
      method: 'POST',
      form: { grant_type: 'refresh_token', client_id: clientId, refresh_token: renewed.refresh_token, resource },
    })
  ).value;
  assert.equal(
    replayed.refresh_token,
    refreshed.refresh_token,
    'bounded refresh grace returns identical rotated token',
  );
  const parallelRenewal = await Promise.all(
    [0, 1].map(() =>
      request('/api/auth/oauth2/token', {
        method: 'POST',
        form: { grant_type: 'refresh_token', client_id: clientId, refresh_token: refreshed.refresh_token, resource },
      }),
    ),
  );
  assert.equal(
    parallelRenewal[0].value.refresh_token,
    parallelRenewal[1].value.refresh_token,
    'concurrent refresh returns one active successor',
  );
  await mcp(refreshed.access_token);
  await request('/admin/clients/' + clientId, { method: 'DELETE', owner: true });
  await mcp(refreshed.access_token, 'tools/list', {}, 401);
  await request('/api/auth/oauth2/token', {
    method: 'POST',
    form: { grant_type: 'refresh_token', client_id: clientId, refresh_token: refreshed.refresh_token, resource },
    expected: 400,
  });
  console.log(
    `Remote OAuth acceptance passed: ${passed} HTTP assertions; closed registration, signed login/consent, S256 PKCE, audience validation, refresh, code replay, and immediate installation revocation.`,
  );
  return passed;
}
