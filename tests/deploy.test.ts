import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import type { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deploy } from '../scripts/deploy.mjs';
import { parseRootKeys } from '../packages/core/crypto';
import { VERSION } from '../apps/worker/src/context';

const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };

// wrangler and the network are fakes; everything the deploy entry writes goes to a temporary project.
type Binding = { type: string; name: string; database_id?: string; bucket_name?: string };
// The bindings of every version of the current deployment.
type Worker = { versions: Binding[][]; rootKey: boolean };
// A failure with a code (written to wrangler's output file), with a message only, or with no
// output-file entry at all and only stderr.
type Failure = number | { code?: number; message?: string; stderr?: string };
type Scenario = {
  worker: Worker | null;
  // 'unmigrated': the database has no tables yet.
  initialized: boolean | 'unmigrated';
  applied?: string[];
  // D1 database ids that no longer exist; every other id does.
  deleted?: string[];
  // wrangler commands (such as "secret put ROOT_KEY") that fail, one failure per call, in order.
  failures?: Record<string, Failure[]>;
  auth?: object;
  domains?: { hostname?: string; service?: string }[];
  // DNS-over-HTTPS answers by record type; absent types do not exist (status 3).
  dns?: Record<string, object>;
  health?: (object | Error)[];
  vault?: { result: { key: string }[]; result_info: { is_truncated: boolean; cursor?: string } }[];
};
type Call = { file: string; command: string; args: string[]; env?: NodeJS.ProcessEnv; input?: string };

const ids = {
  staging: '11111111-1111-4111-8111-111111111111',
  production: '22222222-2222-4222-8222-222222222222',
  fresh: '33333333-3333-4333-8333-333333333333',
};
const environment = (name: 'staging' | 'production') => ({
  name: `svc-${name}`,
  routes: [{ pattern: `${name}.vault.test`, custom_domain: true }],
  vars: { APP_ORIGIN: `https://${name}.vault.test`, ALLOW_LOCAL_HTTP: 'false' },
  d1_databases: [{ binding: 'DB', database_name: `svc-${name}`, database_id: ids[name], migrations_dir: 'migrations' }],
  r2_buckets: [{ binding: 'BACKUPS', bucket_name: `svc-${name}-backups` }],
  triggers: { crons: ['*/15 * * * *'] },
  secrets: { required: ['ROOT_KEY'] },
});
const configuration = () => ({
  name: 'svc',
  account_id: 'abcdef0123456789abcdef0123456789',
  main: 'index.ts',
  compatibility_date: '2026-09-11',
  d1_databases: [{ binding: 'DB', database_name: 'svc-local', migrations_dir: 'migrations' }],
  r2_buckets: [{ binding: 'BACKUPS', bucket_name: 'svc-backups-local' }],
  vars: { APP_ORIGIN: 'http://localhost:8787', ALLOW_LOCAL_HTTP: 'true' },
  env: { staging: environment('staging'), production: environment('production') } as Record<string, any>,
});
const d1 = (database_id: string, name = 'DB'): Binding => ({ type: 'd1', name, database_id });
const r2 = (bucket_name: string, name = 'BACKUPS'): Binding => ({ type: 'r2_bucket', name, bucket_name });
const stagingBindings = () => [d1(ids.staging), r2('svc-staging-backups')];
const bound = (rootKey = true, bindings = stagingBindings()): Worker => ({ versions: [bindings], rootKey });
const placeholder = (rootKey: boolean): Worker => ({ versions: [[]], rootKey });
const ready = (initialized: boolean) => ({
  ok: true,
  version: pkg.version,
  keys: initialized ? 'ok' : 'uninitialized',
  initialized,
});

let root: string;
let output: string[];
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'clavifer-deploy-test-'));
  mkdirSync(join(root, 'migrations'));
  writeFileSync(join(root, 'migrations', '0001_initial.sql'), 'CREATE TABLE t (id TEXT);\n');
  writeFileSync(join(root, 'index.ts'), 'export default {};\n');
  output = [];
  const record = (...parts: unknown[]) => void output.push(parts.join(' '));
  vi.spyOn(console, 'log').mockImplementation(record);
  vi.spyOn(console, 'error').mockImplementation(record);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  rmSync(root, { recursive: true, force: true });
});

// Runs the deploy entry against a fake wrangler and a fake network holding the scenario.
async function run(argv: string[], scenario: Scenario, config = configuration()) {
  writeFileSync(join(root, 'wrangler.jsonc'), JSON.stringify(config));
  const calls: Call[] = [];
  const fetched: string[] = [];
  const failures = structuredClone(scenario.failures ?? {});
  const health = [...(scenario.health ?? [])];
  const spawn = (file: string, args: string[], options: { env?: NodeJS.ProcessEnv; input?: string }) => {
    if (file !== process.execPath) {
      calls.push({ file, command: file, args });
      return { status: 0 };
    }
    // The words before --config, without the SQL after --command.
    const rest = args.slice(1);
    const sql = rest.indexOf('--command');
    const command = rest.slice(0, sql < 0 ? rest.indexOf('--config') : sql + 1).join(' ');
    calls.push({ file, command, args: rest, env: options.env, input: options.input });
    const fail = (failure: Failure) => {
      const { code, message, stderr } = typeof failure === 'number' ? { code: failure, message: 'failed' } : failure;
      if (message !== undefined)
        writeFileSync(
          options.env!.WRANGLER_OUTPUT_FILE_PATH!,
          JSON.stringify({ type: 'command-failed', code, message }) + '\n',
        );
      return { status: 1, stdout: '', stderr: stderr ?? '' };
    };
    if (failures[command]?.length) return fail(failures[command].shift()!);
    const ok = (value: unknown) => ({ status: 0, stdout: JSON.stringify(value) });
    const worker = scenario.worker;
    if (command === 'deployments status --json')
      return worker
        ? ok({ versions: worker.versions.map((_, i) => ({ version_id: `v${i}`, percentage: 50 })) })
        : fail(10007);
    const view = /^versions view v(\d+) --json$/.exec(command);
    if (view) return ok({ resources: { bindings: worker!.versions[Number(view[1])] } });
    const info = /^d1 info (\S+) --json$/.exec(command);
    // What wrangler 4.149.0 reports for an id the API answers 404 for (getDatabaseByNameOrBinding).
    if (info)
      return scenario.deleted?.includes(info[1])
        ? fail({
            message: `Couldn't find a D1 DB with name or binding '${info[1]}' in your config or the API. Run 'wrangler d1 create ${info[1]}' to create it.`,
          })
        : ok({ uuid: info[1], name: 'some-database' });
    if (command === 'secret list') return ok(worker!.rootKey ? [{ name: 'ROOT_KEY', type: 'secret_text' }] : []);
    if (command === 'auth token --json') return ok(scenario.auth ?? { type: 'oauth', token: 'test-oauth-token' });
    if (command === 'secret put ROOT_KEY') {
      scenario.worker = worker ? { ...worker, rootKey: true } : placeholder(true);
      return { status: 0, stdout: null };
    }
    if (command.startsWith('d1 execute')) {
      const statement = rest[sql + 1];
      if (statement.startsWith('SELECT') && statement.includes('owner_user_id'))
        return scenario.initialized === 'unmigrated'
          ? fail({ message: '{"error":{"text":"no such table: system_state: SQLITE_ERROR [code: 7500]"}}' })
          : ok([{ results: scenario.initialized ? [{ 1: 1 }] : [] }]);
      if (statement.includes('d1_migrations'))
        return ok([{ results: (scenario.applied ?? ['0001_initial.sql']).map((name) => ({ name })) }]);
      if (statement.includes('bootstrap_token')) return ok([{ results: [] }]);
    }
    if (['d1 migrations apply DB --remote', 'd1 migrations apply DB --local', 'deploy'].includes(command))
      return { status: 0, stdout: null };
    throw new Error(`unexpected wrangler ${command}`);
  };
  const fetch = async (url: string) => {
    fetched.push(url);
    const json = (value: unknown) => new Response(JSON.stringify(value));
    if (url.includes('/workers/domains?hostname=')) return json({ success: true, result: scenario.domains ?? [] });
    if (url.startsWith('https://cloudflare-dns.com/dns-query?')) {
      const type = new URL(url).searchParams.get('type')!;
      return json(scenario.dns?.[type] ?? { Status: 3 });
    }
    if (url.endsWith('/healthz')) {
      const next = health.length > 1 ? health.shift()! : (health[0] ?? ready(scenario.initialized === true));
      if (next instanceof Error) throw next;
      return json(next);
    }
    if (url.includes('/r2/buckets/')) return json({ success: true, ...scenario.vault!.shift()! });
    throw new Error(`unexpected fetch ${url}`);
  };
  const sleep = vi.fn(async () => {});
  const result = deploy(argv, {
    root,
    spawn: spawn as unknown as typeof spawnSync,
    fetch: fetch as unknown as typeof globalThis.fetch,
    sleep,
  });
  return { result, calls, fetched, sleep, commands: () => calls.map((call) => call.command) };
}
const first = (): Scenario => ({ worker: null, initialized: 'unmigrated' });
const upgrade = (more: Partial<Scenario> = {}): Scenario => ({ worker: bound(), initialized: true, ...more });
const reads = /^(deployments status|versions view|secret list|auth token|d1 execute|d1 info)/;

describe('static refusals', () => {
  const refusals: [string, (c: ReturnType<typeof configuration>) => void, string][] = [
    ['no account_id', (c) => delete (c as any).account_id, 'account_id in wrangler.jsonc is missing'],
    ['the zeroed account_id', (c) => (c.account_id = '0'.repeat(32)), "the template's all-zero placeholder"],
    ['no database_id', (c) => delete c.env.staging.d1_databases[0].database_id, 'has no database_id'],
    [
      'the zeroed database_id',
      (c) => (c.env.staging.d1_databases[0].database_id = '00000000-0000-0000-0000-000000000000'),
      "still has the template's all-zero database_id",
    ],
    ['no bucket', (c) => (c.env.staging.r2_buckets = []), 'has no R2 bucket'],
    ['no route', (c) => (c.env.staging.routes = []), 'exactly one route'],
    [
      'two routes',
      (c) => c.env.staging.routes.push({ pattern: 'other.vault.test', custom_domain: true }),
      'exactly one route',
    ],
    [
      'a zone route',
      (c) => (c.env.staging.routes = [{ pattern: 'staging.vault.test/*', zone_name: 'vault.test' }]),
      'custom domain',
    ],
    [
      'an example.com hostname in any case',
      (c) => {
        c.env.staging.routes[0].pattern = 'Credentials.Example.COM';
        c.env.staging.vars.APP_ORIGIN = 'https://Credentials.Example.COM';
      },
      "still has the template's hostname Credentials.Example.COM",
    ],
    [
      'APP_ORIGIN on another host',
      (c) => (c.env.staging.vars.APP_ORIGIN = 'https://other.vault.test'),
      'it must be https://staging.vault.test',
    ],
    ['no cron', (c) => (c.env.staging.triggers.crons = []), 'has no cron trigger'],
    ['no secrets.required', (c) => delete c.env.staging.secrets, '"required": ["ROOT_KEY"]'],
    ['ALLOW_LOCAL_HTTP', (c) => (c.env.staging.vars.ALLOW_LOCAL_HTTP = 'true'), 'ALLOW_LOCAL_HTTP'],
    ['a shared Worker name', (c) => (c.env.production.name = 'svc-staging'), 'share the Worker name svc-staging'],
    [
      'a shared database',
      (c) => (c.env.production.d1_databases[0].database_id = ids.staging),
      `share the database_id ${ids.staging}`,
    ],
    [
      'a shared bucket',
      (c) => (c.env.production.r2_buckets[0].bucket_name = 'svc-staging-backups'),
      'share the R2 bucket svc-staging-backups',
    ],
    [
      'a shared hostname',
      (c) => (c.env.production.routes[0].pattern = 'staging.vault.test'),
      'share the hostname staging.vault.test',
    ],
    ['no environments', (c) => delete (c as any).env, 'has no environment "staging"'],
  ];
  it.each(refusals)('refuses %s before calling wrangler', async (_, change, message) => {
    const config = configuration();
    change(config);
    const { result, calls, fetched } = await run(['--env', 'staging'], first(), config);
    await expect(result).rejects.toThrow(message);
    expect(calls).toEqual([]);
    expect(fetched).toEqual([]);
  });
  it('requires --env', async () => {
    const { result, calls } = await run([], first());
    await expect(result).rejects.toThrow('--env is required');
    expect(calls).toEqual([]);
  });
  it('compares the top level with no environment', async () => {
    const config = configuration();
    config.r2_buckets[0].bucket_name = 'svc-staging-backups';
    const { result } = await run(['--env', 'staging'], first(), config);
    await expect(result).resolves.toBeUndefined();
  });
});

describe('consistency refusals', () => {
  const refusals: [string, Scenario, string][] = [
    [
      'a Worker bound to another database',
      upgrade({ worker: bound(true, [d1(ids.fresh), r2('svc-staging-backups')]) }),
      `has the D1 binding DB=${ids.fresh}, not DB=${ids.staging}`,
    ],
    [
      'the right database under another binding name',
      upgrade({ worker: bound(true, [d1(ids.staging, 'OTHER'), r2('svc-staging-backups')]) }),
      `has the D1 binding OTHER=${ids.staging}`,
    ],
    [
      'a Worker bound to another bucket',
      upgrade({ worker: bound(true, [d1(ids.staging), r2('elsewhere')]) }),
      'has the R2 binding BACKUPS=elsewhere, not BACKUPS=svc-staging-backups',
    ],
    [
      'a gradual deployment whose second version is bound elsewhere',
      upgrade({ worker: { versions: [stagingBindings(), [d1(ids.fresh), r2('svc-staging-backups')]], rootKey: true } }),
      `has the D1 binding DB=${ids.fresh}`,
    ],
    [
      'a hostname on another Worker',
      upgrade({ domains: [{ hostname: 'STAGING.vault.test', service: 'someone-else' }] }),
      'staging.vault.test is attached to the Worker someone-else',
    ],
    [
      'a hostname whose domain record names no Worker',
      upgrade({ domains: [{ hostname: 'staging.vault.test' }] }),
      'staging.vault.test is attached to the Worker (none named)',
    ],
    [
      'a hostname that already resolves',
      upgrade({ dns: { CNAME: { Status: 0, Answer: [{ data: 'elsewhere.test.' }] } } }),
      'staging.vault.test already resolves in DNS',
    ],
    [
      'a failed DNS lookup',
      upgrade({ dns: { AAAA: { Status: 2 } } }),
      'the DNS lookup of staging.vault.test (AAAA) failed',
    ],
    [
      'no Worker for an initialized database',
      { worker: null, initialized: true },
      'the Worker svc-staging does not exist',
    ],
    [
      'a placeholder Worker for an initialized database',
      { worker: placeholder(true), initialized: true },
      'the Worker svc-staging is only a placeholder',
    ],
    [
      'an initialized database whose Worker lost ROOT_KEY',
      { worker: bound(false), initialized: true },
      'has no ROOT_KEY, but its database is initialized',
    ],
    [
      'a Worker with neither bindings nor ROOT_KEY',
      { worker: placeholder(false), initialized: 'unmigrated' },
      'the Worker svc-staging exists but has neither the D1 and R2 bindings of this configuration nor a ROOT_KEY',
    ],
    [
      'a Worker with only other bindings and no ROOT_KEY',
      { worker: { versions: [[{ type: 'kv_namespace', name: 'CACHE' }]], rootKey: false }, initialized: false },
      'it is not a Clavifer instance of this configuration',
    ],
  ];
  it.each(refusals)('refuses %s before writing anything', async (_, scenario, message) => {
    const { result, commands } = await run(['--env', 'staging'], scenario);
    await expect(result).rejects.toThrow(message);
    expect(commands().filter((c) => !reads.test(c))).toEqual([]);
  });
  it("accepts the hostname as this Worker's own custom domain without a DNS lookup", async () => {
    const { result, fetched } = await run(
      ['--env', 'staging'],
      upgrade({
        domains: [{ hostname: 'staging.vault.test', service: 'svc-staging' }],
        dns: { A: { Status: 0, Answer: [{ data: 'elsewhere.test.' }] } },
      }),
    );
    await result;
    expect(fetched.some((url) => url.includes('dns-query'))).toBe(false);
  });
  it('stops on a deployments status failure other than a missing Worker', async () => {
    const { result, commands } = await run(['--env', 'staging'], {
      ...first(),
      failures: { 'deployments status --json': [10000] },
    });
    await expect(result).rejects.toThrow('wrangler deployments status failed');
    expect(commands()).toEqual(['deployments status --json']);
  });
  it('stops when the instance state cannot be read for another reason than a missing table', async () => {
    const { result, commands } = await run(['--env', 'staging'], {
      ...first(),
      failures: {
        'd1 execute DB --remote --json --command': [{ message: '{"error":{"text":"D1_ERROR: overloaded"}}' }],
      },
    });
    await expect(result).rejects.toThrow(
      'd1 execute (read the instance state) failed: {"error":{"text":"D1_ERROR: overloaded"}}',
    );
    expect(commands().filter((c) => !reads.test(c))).toEqual([]);
  });
  it('refuses a session signed in with an API key and email', async () => {
    const { result, fetched } = await run(['--env', 'staging'], {
      ...first(),
      auth: { type: 'api_key', key: 'test-key', email: 'test-email' },
    });
    await expect(result).rejects.toThrow('signed in with CLOUDFLARE_API_KEY and CLOUDFLARE_EMAIL');
    expect(fetched).toEqual([]);
  });
});

describe('the root key', () => {
  const puts = (calls: Call[]) => calls.filter((call) => call.command === 'secret put ROOT_KEY');
  it.each([
    ['no Worker', null],
    ['a Worker with bindings but no ROOT_KEY', bound(false)],
  ])('is generated for an uninitialized database and %s', async (_, worker) => {
    const { result, calls, commands } = await run(['--env', 'staging'], { worker, initialized: 'unmigrated' });
    await result;
    expect(puts(calls)).toHaveLength(1);
    expect(parseRootKeys(puts(calls)[0].input!)).toHaveLength(1);
    expect(commands()).toEqual([
      'deployments status --json',
      ...(worker ? ['versions view v0 --json', 'secret list'] : []),
      'auth token --json',
      'd1 execute DB --remote --json --command',
      'secret put ROOT_KEY',
      'd1 migrations apply DB --remote',
      'd1 execute DB --remote --json --command',
      'npm run build:web',
      'deploy',
      'd1 execute DB --remote --json --command',
    ]);
  });
  it('is not replaced when a placeholder Worker already has one: a first run stopped after storing it', async () => {
    const { result, calls } = await run(['--env', 'staging'], { worker: placeholder(true), initialized: false });
    await result;
    expect(puts(calls)).toEqual([]);
    expect(calls.some((call) => call.command === 'deploy')).toBe(true);
  });
  it('is left alone on an upgrade, and no token is issued', async () => {
    const { result, calls } = await run(['--env', 'staging'], upgrade());
    await result;
    expect(puts(calls)).toEqual([]);
    expect(calls.some((call) => call.args.some((arg) => arg.includes('bootstrap_token')))).toBe(false);
    expect(readdirSync(root)).not.toContain('work');
  });
  it('reaches wrangler only on stdin, never in arguments, files or output', async () => {
    const { result, calls } = await run(['--env', 'staging'], first());
    await result;
    const key = puts(calls)[0].input!;
    expect(calls.filter((call) => call.input !== undefined)).toHaveLength(1);
    for (const call of calls) expect(call.args.join(' ')).not.toContain(key);
    expect(output.join('\n')).not.toContain(key);
    expect(output.join('\n')).not.toContain(key.slice(2));
    const files = (dir: string): string[] =>
      readdirSync(dir).flatMap((name) =>
        statSync(join(dir, name)).isDirectory() ? files(join(dir, name)) : [join(dir, name)],
      );
    for (const file of files(root)) expect(readFileSync(file, 'utf8')).not.toContain(key.slice(2));
  });
  it('is reused when wrangler retries a transient failure', async () => {
    const { result, calls } = await run(['--env', 'staging'], {
      ...first(),
      failures: { 'secret put ROOT_KEY': [10013] },
    });
    await result;
    expect(puts(calls)).toHaveLength(2);
    expect(puts(calls)[1].input).toBe(puts(calls)[0].input);
  });
  it('is put through children that sanitize their logs whatever the environment says', async () => {
    // Another spelling of the name: the same variable on Windows, where the child would see both.
    vi.stubEnv('Wrangler_Log_Sanitize', 'false');
    const { result, calls } = await run(['--env', 'staging'], first());
    await result;
    const wranglerCalls = calls.filter((call) => call.file === process.execPath);
    expect(wranglerCalls.length).toBeGreaterThan(5);
    for (const call of wranglerCalls) {
      const names = Object.keys(call.env!).filter((name) => name.toUpperCase() === 'WRANGLER_LOG_SANITIZE');
      expect(names.map((name) => call.env![name])).toEqual(['true']);
    }
  });
  it('is never in a log file: only the auth token call, which prints a token, turns logs off', async () => {
    const { result, calls } = await run(['--env', 'staging'], first());
    await result;
    const quiet = calls.filter((call) => call.env?.WRANGLER_WRITE_LOGS === 'false').map((call) => call.command);
    expect(quiet).toEqual(['auth token --json']);
  });
});

describe('the deployment', () => {
  it('retries a transient wrangler failure once, then stops', async () => {
    const once = await run(['--env', 'staging'], upgrade({ failures: { deploy: [7403] } }));
    await once.result;
    expect(once.commands().filter((c) => c === 'deploy')).toHaveLength(2);
    const twice = await run(['--env', 'staging'], upgrade({ failures: { deploy: [10013, 10013] } }));
    await expect(twice.result).rejects.toThrow('wrangler deploy failed');
    expect(twice.commands().filter((c) => c === 'deploy')).toHaveLength(2);
  });
  it('retries a d1 execute whose 7403 is only in the message', async () => {
    const { result, commands } = await run(['--env', 'staging'], {
      ...first(),
      failures: {
        'd1 execute DB --remote --json --command': [
          { message: '{"error":{"text":"A request failed.","notes":[{"text":"no access [code: 7403]"}]}}' },
        ],
      },
    });
    await result;
    expect(commands().slice(0, 5)).toEqual([
      'deployments status --json',
      'auth token --json',
      'd1 execute DB --remote --json --command',
      'd1 execute DB --remote --json --command',
      'secret put ROOT_KEY',
    ]);
  });
  it('does not retry other failures', async () => {
    const { result, commands } = await run(['--env', 'staging'], upgrade({ failures: { deploy: [10021] } }));
    await expect(result).rejects.toThrow('wrangler deploy failed');
    expect(commands().filter((c) => c === 'deploy')).toHaveLength(1);
  });
  it("reports wrangler's stderr when it left no failure entry", async () => {
    const { result } = await run(
      ['--env', 'staging'],
      upgrade({ failures: { 'secret list': [{ stderr: 'unexpected crash\n' }] } }),
    );
    await expect(result).rejects.toThrow('wrangler secret list failed: exited with status 1: unexpected crash');
  });
  it('stops before deploying when d1_migrations does not match the migrations directory', async () => {
    const { result, commands } = await run(['--env', 'staging'], upgrade({ applied: [] }));
    await expect(result).rejects.toThrow(
      'the database lists the migrations (none), but migrations has 0001_initial.sql',
    );
    expect(commands()).not.toContain('npm run build:web');
    expect(commands()).not.toContain('deploy');
  });
  it('issues a token for an uninitialized instance and prints only its path', async () => {
    const { result, calls } = await run(['--env', 'staging'], first());
    await result;
    const token = readFileSync(join(root, 'work', 'staging-bootstrap.token'), 'utf8');
    const hash = createHash('sha256').update(token).digest('base64url');
    const issue = calls.find((call) => call.args.some((arg) => arg.includes('bootstrap_token')))!;
    expect(issue.args).toContain('--remote');
    expect(issue.args.join(' ')).toContain(`json_object('hash','${hash}'`);
    expect(issue.args.join(' ')).not.toContain(token);
    expect(output.join('\n')).toContain(join('work', 'staging-bootstrap.token'));
    expect(output.join('\n')).not.toContain(token);
  });
  it('replaces an earlier token file with --issue-token on an initialized instance', async () => {
    mkdirSync(join(root, 'work'));
    writeFileSync(join(root, 'work', 'staging-bootstrap.token'), 'stale');
    const { result } = await run(['--env', 'staging', '--issue-token'], upgrade());
    await result;
    expect(readFileSync(join(root, 'work', 'staging-bootstrap.token'), 'utf8')).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it('waits for /healthz to answer the new version', async () => {
    const { result, sleep } = await run(
      ['--env', 'staging'],
      upgrade({ health: [new Error('certificate not yet valid'), { ...ready(true), version: '0.4.0' }, ready(true)] }),
    );
    await result;
    expect(sleep).toHaveBeenCalledTimes(2);
  });
  it.each([
    ['the wrong keys', { ...ready(true), keys: 'mismatch', ok: false }],
    ['no keys', { ok: true, version: pkg.version, initialized: true }],
  ])('gives up on /healthz answering %s after 10 minutes', async (_, answer) => {
    const { result, sleep } = await run(['--env', 'staging'], upgrade({ health: [answer] }));
    await expect(result).rejects.toThrow('did not answer');
    expect(sleep).toHaveBeenCalledTimes(60);
  });
});

describe('--rebuild', () => {
  const broken = { ok: false, version: pkg.version, keys: 'mismatch', initialized: true };
  const fresh = () => {
    const config = configuration();
    config.env.staging.d1_databases[0].database_id = ids.fresh;
    return config;
  };
  const vault = () => [
    { result: [{ key: 'vault/2026-10-01/1790800000000-a.age' }], result_info: { is_truncated: false } },
  ];
  it.each([
    ['works with its key', ready(true)],
    ['fails for another reason', { error: 'internal_error' }],
  ])('refuses while the instance %s and its database still exists', async (_, health) => {
    const { result, commands } = await run(
      ['--env', 'staging', '--rebuild'],
      { worker: bound(), initialized: false, health: [health] },
      fresh(),
    );
    await expect(result).rejects.toThrow(
      `not a lost or replaced root key, and the database ${ids.staging} of the Worker svc-staging still exists`,
    );
    expect(commands()).toContain(`d1 info ${ids.staging} --json`);
    expect(commands().filter((c) => !reads.test(c))).toEqual([]);
  });
  it.each([
    ['no Worker', null, 'the Worker svc-staging does not exist'],
    ['a placeholder Worker', placeholder(true), 'the Worker svc-staging has no D1 binding'],
  ])('refuses %s, which has no database that could have been deleted', async (_, worker, message) => {
    const { result, commands } = await run(
      ['--env', 'staging', '--rebuild'],
      { worker, initialized: 'unmigrated', health: [{ error: 'internal_error' }] },
      fresh(),
    );
    await expect(result).rejects.toThrow(message);
    expect(commands().filter((c) => !reads.test(c))).toEqual([]);
  });
  it('refuses a gradual deployment one of whose databases still exists', async () => {
    const { result, commands } = await run(
      ['--env', 'staging', '--rebuild'],
      {
        worker: { versions: [stagingBindings(), [d1(ids.production), r2('svc-staging-backups')]], rootKey: true },
        initialized: 'unmigrated',
        deleted: [ids.staging],
        health: [{ error: 'internal_error' }],
      },
      fresh(),
    );
    await expect(result).rejects.toThrow(`the database ${ids.production} of the Worker svc-staging still exists`);
    expect(commands().filter((c) => !reads.test(c))).toEqual([]);
  });
  it('stops when wrangler cannot tell whether the database exists', async () => {
    const { result, commands } = await run(
      ['--env', 'staging', '--rebuild'],
      {
        worker: bound(),
        initialized: 'unmigrated',
        health: [{ error: 'internal_error' }],
        failures: { [`d1 info ${ids.staging} --json`]: [{ message: 'Authentication error [code: 10000]' }] },
      },
      fresh(),
    );
    await expect(result).rejects.toThrow('wrangler d1 info failed: Authentication error [code: 10000]');
    expect(commands().filter((c) => !reads.test(c))).toEqual([]);
  });
  it('goes on with a new key when the database the Worker is bound to was deleted', async () => {
    const { result, calls, commands } = await run(
      ['--env', 'staging', '--rebuild'],
      {
        worker: bound(),
        initialized: 'unmigrated',
        deleted: [ids.staging],
        health: [{ error: 'internal_error' }, ready(false)],
        vault: vault(),
      },
      fresh(),
    );
    await result;
    expect(commands()).toContain(`d1 info ${ids.staging} --json`);
    expect(calls.filter((call) => call.command === 'secret put ROOT_KEY')).toHaveLength(1);
    expect(commands()).toContain('deploy');
  });
  it('goes on for a ROOT_KEY that cannot be parsed, without looking at the database', async () => {
    const { result, calls, commands } = await run(
      ['--env', 'staging', '--rebuild'],
      {
        worker: bound(),
        initialized: 'unmigrated',
        health: [{ error: 'invalid_root_key' }, ready(false)],
        vault: vault(),
      },
      fresh(),
    );
    await result;
    expect(calls.filter((call) => call.command === 'secret put ROOT_KEY')).toHaveLength(1);
    expect(commands().some((c) => c.startsWith('d1 info'))).toBe(false);
  });
  it('refuses an initialized target database', async () => {
    const { result, commands } = await run(
      ['--env', 'staging', '--rebuild'],
      { worker: bound(), initialized: true, health: [broken] },
      fresh(),
    );
    await expect(result).rejects.toThrow('--rebuild only goes into a new, uninitialized database');
    expect(commands()).not.toContain('secret put ROOT_KEY');
  });
  it('rebinds the Worker to the new database with a new key and prints the latest automatic backup', async () => {
    const { result, calls, fetched } = await run(
      ['--env', 'staging', '--rebuild'],
      {
        worker: bound(),
        initialized: 'unmigrated',
        health: [broken, ready(false)],
        vault: [
          {
            result: [{ key: 'vault/2026-10-02/1790900000000-b.age' }, { key: 'vault/2026-10-01/1790800000000-a.age' }],
            result_info: { is_truncated: true, cursor: 'next' },
          },
          { result: [{ key: 'vault/2026-10-03/1791000000000-c.age' }], result_info: { is_truncated: false } },
        ],
      },
      fresh(),
    );
    await result;
    expect(calls.filter((call) => call.command === 'secret put ROOT_KEY')).toHaveLength(1);
    expect(calls.map((call) => call.command)).toContain('deploy');
    expect(readFileSync(join(root, 'work', 'staging-bootstrap.token'), 'utf8')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(fetched.filter((url) => url.includes('/r2/buckets/svc-staging-backups/objects?prefix=vault/'))).toHaveLength(
      2,
    );
    expect(fetched.at(-1)).toContain('cursor=next');
    expect(output.join('\n')).toContain('Latest automatic backup: vault/2026-10-03/1791000000000-c.age');
  });
  it('still refuses another bucket', async () => {
    const { result } = await run(
      ['--env', 'staging', '--rebuild'],
      { worker: bound(true, [d1(ids.staging), r2('elsewhere')]), initialized: 'unmigrated', health: [broken] },
      fresh(),
    );
    await expect(result).rejects.toThrow('has the R2 binding BACKUPS=elsewhere');
  });
});

describe('--local', () => {
  it('creates .dev.vars, migrates the local database and issues a token', async () => {
    const { result, calls } = await run(['--local'], first());
    await result;
    const vars = readFileSync(join(root, '.dev.vars'), 'utf8');
    expect(vars).toMatch(/^ROOT_KEY=[^\n]+\n$/);
    expect(parseRootKeys(vars.trim().slice('ROOT_KEY='.length))).toHaveLength(1);
    expect(output.join('\n')).not.toContain(vars.trim().slice('ROOT_KEY=1:'.length));
    expect(calls.map((call) => call.command)).toEqual([
      'd1 migrations apply DB --local',
      'd1 execute DB --local --json --command',
    ]);
    for (const call of calls) expect(call.args).not.toContain('--env');
    const token = readFileSync(join(root, 'work', 'local-bootstrap.token'), 'utf8');
    expect(calls[1].args.join(' ')).toContain(createHash('sha256').update(token).digest('base64url'));
  });
  it('keeps an existing .dev.vars with a valid ROOT_KEY', async () => {
    const existing = `OTHER=1\nROOT_KEY=2:${randomBytes(32).toString('base64url')}\n`;
    writeFileSync(join(root, '.dev.vars'), existing);
    const { result } = await run(['--local'], first());
    await result;
    expect(readFileSync(join(root, '.dev.vars'), 'utf8')).toBe(existing);
    expect(output.join('\n')).not.toContain(existing.split('ROOT_KEY=2:')[1].trim());
    expect(readFileSync(join(root, 'work', 'local-bootstrap.token'), 'utf8')).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it.each([
    ['older names only', 'KEK_RING=old-value-not-printed\nAUTH_SECRET=other-value-not-printed\n'],
    ['an invalid ROOT_KEY', 'ROOT_KEY=old-value-not-printed\n'],
  ])('refuses an existing .dev.vars with %s and leaves it alone', async (_, existing) => {
    writeFileSync(join(root, '.dev.vars'), existing);
    const { result, calls } = await run(['--local'], first());
    await expect(result).rejects.toThrow(
      /from an older version.*Deleting it loses the key the local data is encrypted with/s,
    );
    await result.catch((error: Error) => expect(error.message).not.toContain('not-printed'));
    expect(output.join('\n')).not.toContain('not-printed');
    expect(readFileSync(join(root, '.dev.vars'), 'utf8')).toBe(existing);
    expect(calls).toEqual([]);
  });
  it('takes no environment', async () => {
    const { result, calls } = await run(['--local', '--env', 'staging'], first());
    await expect(result).rejects.toThrow('--local takes only --config');
    expect(calls).toEqual([]);
  });
});

// The deployment is accepted when /healthz reports the version of package.json, so the Worker and the
// CLI it is released with carry the same one (the OpenAPI document takes the Worker's).
it('expects the version the Worker and the CLI report', () => {
  expect(VERSION).toBe(pkg.version);
  expect(readFileSync('cmd/clavifer/main.go', 'utf8')).toContain(`const cliVersion = "${pkg.version}"`);
});
