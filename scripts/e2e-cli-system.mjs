// Production executable + real OS credential store, using only synthetic loopback credentials.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { randomUUID, randomBytes } from 'node:crypto';
import { resolve, join } from 'node:path';
import { readFile, readdir } from 'node:fs/promises';
import assert from 'node:assert/strict';

assert.equal(process.platform, 'win32', 'This acceptance script targets Windows Credential Manager.');
const binary = resolve(process.env.CLAVIFER_CLI_BINARY ?? 'dist/clavifer.exe');
const version = JSON.parse(await readFile('package.json', 'utf8')).version;
const suffix = randomUUID().slice(0, 8);
const names = ['codex', 'claude'].map((n) => `acceptance-${n}-${suffix}`);
const accounts = new Map(
  names.map((name) => [
    name,
    { access: randomBytes(24).toString('hex'), refresh: randomBytes(24).toString('hex'), refreshes: 0, revoked: false },
  ]),
);
const secret = 'CLAVIFER_SYNTHETIC_' + randomBytes(16).toString('hex');
let origin;
let secretReads = 0;
const server = createServer(async (req, res) => {
  let raw = '';
  for await (const b of req) raw += b;
  const reply = (status, value) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(value));
  };
  if (req.url === '/healthz') return reply(200, { ok: true, service: 'clavifer', version });
  if (req.url === '/api/auth/device/code') {
    const input = JSON.parse(raw);
    if (!accounts.has(input.client_id)) return reply(400, { error: 'unknown_test_client' });
    return reply(200, {
      device_code: input.client_id,
      user_code: 'SYNTHETIC',
      verification_uri: origin + '/device',
      expires_in: 60,
      interval: 5,
    });
  }
  if (req.url === '/api/auth/oauth2/token') {
    const form = new URLSearchParams(raw),
      account = accounts.get(form.get('client_id'));
    if (!account || account.revoked) return reply(400, { error: 'invalid_grant' });
    if (form.get('grant_type') === 'refresh_token') {
      if (form.get('refresh_token') !== account.refresh) return reply(400, { error: 'invalid_grant' });
      account.refreshes++;
      account.access = randomBytes(24).toString('hex');
      account.refresh = randomBytes(24).toString('hex');
      return reply(200, { access_token: account.access, refresh_token: account.refresh, expires_in: 600 });
    }
    return reply(200, { access_token: account.access, refresh_token: account.refresh, expires_in: 1 });
  }
  const entry = [...accounts].find(([, a]) => 'Bearer ' + a.access === req.headers.authorization && !a.revoked);
  if (!entry) return reply(401, { error: 'client_revoked' });
  if (req.url === '/v1/secrets') return reply(200, { items: [{ id: entry[0] }], connections: [] });
  if (req.url === '/v1/secrets/test-secret/read') {
    secretReads++;
    return reply(200, { values: { token: secret } });
  }
  if (req.url === '/v1/mcp') {
    const request = JSON.parse(raw);
    if (request.method === 'initialize')
      return reply(200, {
        jsonrpc: '2.0',
        id: request.id,
        result: {
          protocolVersion: '2025-11-25',
          capabilities: { tools: {} },
          serverInfo: { name: 'clavifer', version },
        },
      });
    if (request.method === 'tools/list')
      return reply(200, {
        jsonrpc: '2.0',
        id: request.id,
        result: {
          tools: ['credentials.list', 'access.request', 'access.status', 'http.request'].map((name) => ({
            name,
            inputSchema: { type: 'object' },
            annotations: { readOnlyHint: ['credentials.list', 'access.status'].includes(name) },
          })),
        },
      });
    return reply(400, { error: 'forbidden_test_operation' });
  }
  if (req.url === '/v1/logout') {
    entry[1].revoked = true;
    return reply(200, { ok: true });
  }
  return reply(404, { error: 'not_found' });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
origin = `http://127.0.0.1:${server.address().port}`;
async function cli(profile, args) {
  return await new Promise((resolve, reject) => {
    const child = spawn(binary, ['--profile', profile, ...args], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '',
      stderr = '';
    child.stdout.on('data', (b) => (stdout += b));
    child.stderr.on('data', (b) => (stderr += b));
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('System CLI acceptance timed out'));
    }, 40000);
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      assert(!stdout.includes(secret) && !stderr.includes(secret), 'secret leaked to output');
      resolve({ code, stdout, stderr });
    });
  });
}
try {
  for (const name of names) {
    assert.equal(
      (await cli(name, ['login', '--server', origin, '--client-id', name])).code,
      0,
      'production CLI login failed',
    );
    const results = await Promise.all(Array.from({ length: 6 }, () => cli(name, ['list'])));
    for (const result of results) {
      assert.equal(result.code, 0, 'concurrent CLI list failed');
      assert.equal(JSON.parse(result.stdout).items[0].id, name);
    }
    assert.equal(accounts.get(name).refreshes, 1, 'cross-process lock must allow only one rotating refresh');
    const file = await readFile(join(process.env.APPDATA, 'clavifer', 'profiles', name + '.json'), 'utf8');
    assert.deepEqual(Object.keys(JSON.parse(file)).sort(), ['client_id', 'server']);
    const doctor = await cli(name, ['doctor']);
    assert.equal(doctor.code, 0, 'metadata-only doctor failed');
    const diagnosis = JSON.parse(doctor.stdout);
    assert(diagnosis.ok);
    assert.deepEqual(diagnosis.metadata, { secrets: 1, connections: 0 });
    assert.equal(diagnosis.tools.length, 4);
    assert(
      !doctor.stdout.includes(accounts.get(name).access) && !doctor.stdout.includes(accounts.get(name).refresh),
      'doctor must omit bearer and refresh tokens',
    );
  }
  assert.equal(secretReads, 0, 'doctor must not read business secrets');
  const listed = JSON.parse((await cli(names[0], ['profiles', 'list'])).stdout).profiles;
  for (const name of names)
    assert(
      listed.some((p) => p.name === name && p.status === 'configured'),
      'profile missing from metadata list',
    );
  assert.equal(
    (
      await cli(names[0], [
        'run',
        '--bind',
        'MY_TEST_TOKEN=test-secret.token',
        '--bind',
        'MY_TEST_TOKEN_COPY=test-secret.token',
        '--',
        process.execPath,
        '-e',
        'process.exit(process.env.MY_TEST_TOKEN?.startsWith("CLAVIFER_SYNTHETIC_") && process.env.MY_TEST_TOKEN===process.env.MY_TEST_TOKEN_COPY ? 7 : 9)',
      ])
    ).code,
    7,
    'real injected child exit not preserved',
  );
  assert.equal(secretReads, 1, 'multiple fields of one secret must reuse one snapshot');
  assert.equal((await cli(names[0], ['logout'])).code, 0);
  assert(accounts.get(names[0]).revoked);
  assert.equal((await cli(names[1], ['list'])).code, 0, 'other profile must remain usable');
  assert.equal((await cli(names[1], ['logout'])).code, 0);
  const after = JSON.parse((await cli(names[0], ['profiles', 'list'])).stdout).profiles;
  const files = await readdir(join(process.env.APPDATA, 'clavifer', 'profiles'));
  for (const name of names) {
    assert(!after.some((p) => p.name === name), 'logged-out profile remained active');
    assert.equal(
      files.filter((file) => file.startsWith(name + '.json.logged-out-')).length,
      1,
      'logout must preserve exactly one metadata archive',
    );
  }
  console.log(
    'Production Windows CLI passed: real Credential Manager login/read/refresh/delete, independent profiles, cross-process refresh lock, redacted metadata-only doctor, single-snapshot environment injection, exit codes and preserved logout archives.',
  );
} finally {
  for (const name of names) await cli(name, ['logout', '--local']);
  await new Promise((resolve) => server.close(resolve));
}
