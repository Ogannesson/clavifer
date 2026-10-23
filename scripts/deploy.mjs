// The deploy entry: the one way to put an environment of this service on Cloudflare, and to prepare a
// local trial.
//   npm run deploy -- --env <name> [--config <path>] [--issue-token] [--rebuild]
//   npm run deploy -- --local [--config <path>]
// It runs under tsx because it checks an existing .dev.vars with the Worker's own root-key parser.
//
// The chosen environment's configuration is parsed once per run, with wrangler's own reader; every
// check and every wrangler call below uses that result and names --config and --env explicitly, and
// the account comes from the configuration. The root key is generated in this process and reaches
// wrangler only on stdin; it is never written to disk or printed. The bootstrap token goes only to a
// file whose path is printed.
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { unstable_readConfig } from 'wrangler';
import { parseRootKeys } from '../packages/core/crypto.ts';
import { issueToken } from './bootstrap-token.mjs';

const wranglerBin = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url));
const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const zeros = /^[0-]+$/;
const exampleHost = (host) => /(^|\.)example\.com$/.test(host.toLowerCase());
// Errors wrangler occasionally reports for no lasting reason: 7403 (account access) on d1 commands,
// 10013 (unknown error) while uploading assets. Each call is retried once.
const transient = [7403, 10013];
const workerNotFound = [10007, 10090];

/** A new ring holding one root key. */
const newRootKey = () => `1:${randomBytes(32).toString('base64url')}`;

// What an environment deploys to; the fields two environments must never share.
function target(config) {
  return {
    'Worker name': config.name,
    database_id: config.d1_databases.find((d) => d.binding === 'DB')?.database_id,
    'R2 bucket': config.r2_buckets.find((b) => b.binding === 'BACKUPS')?.bucket_name,
    hostname: config.routes?.length === 1 ? config.routes[0].pattern : undefined,
  };
}

// Refusals that need nothing but the configuration. The first one that applies stops.
function refuseStatic(config, env, readEnv, configPath) {
  const refuse = (condition, message) => {
    if (condition) throw new Error(message);
  };
  refuse(!config.definedEnvironments.includes(env), `${configPath} has no environment "${env}"`);
  refuse(
    !config.account_id || zeros.test(config.account_id),
    `account_id in ${configPath} is missing or the template's all-zero placeholder; set it to the Cloudflare account to deploy to`,
  );
  const own = target(config);
  refuse(!own.database_id, `env "${env}" has no database_id for the D1 binding DB`);
  refuse(
    zeros.test(own.database_id),
    `env "${env}" still has the template's all-zero database_id; create the D1 database and put its id here`,
  );
  refuse(!own['R2 bucket'], `env "${env}" has no R2 bucket for the binding BACKUPS`);
  refuse(
    config.routes?.length !== 1 || config.routes[0].custom_domain !== true,
    `env "${env}" must have exactly one route, and it must be a custom domain`,
  );
  const host = own.hostname;
  refuse(exampleHost(host), `env "${env}" still has the template's hostname ${host}; use your own`);
  refuse(
    config.vars.APP_ORIGIN !== `https://${host}`,
    `APP_ORIGIN of env "${env}" is ${config.vars.APP_ORIGIN}; it must be https://${host}, the environment's custom domain`,
  );
  refuse(
    !config.triggers?.crons?.length,
    `env "${env}" has no cron trigger; without one nothing seals cold data or makes automatic backups`,
  );
  refuse(
    !config.secrets?.required?.includes('ROOT_KEY'),
    `env "${env}" does not declare "secrets": { "required": ["ROOT_KEY"] } (it is not inherited: every environment needs it)`,
  );
  refuse(
    config.vars.ALLOW_LOCAL_HTTP === 'true',
    `env "${env}" sets ALLOW_LOCAL_HTTP to "true", which is only for local development`,
  );
  // Two instances on one bucket delete each other's backups and mix their cold-data segments. The
  // top level is the local development configuration and takes no part.
  const seen = new Map();
  for (const name of config.definedEnvironments) {
    for (const [field, value] of Object.entries(name === env ? own : target(readEnv(name)))) {
      if (value === undefined) continue;
      const other = seen.get(`${field}\n${value}`);
      refuse(other !== undefined, `env "${other}" and env "${name}" share the ${field} ${value}`);
      seen.set(`${field}\n${value}`, name);
    }
  }
}

/** Runs the deploy entry with argv (without the node and script paths). spawn, fetch and sleep are
 * replaced by the tests; root is the project directory, where work/ and the default config are. */
export async function deploy(
  argv,
  {
    root = process.cwd(),
    spawn = spawnSync,
    fetch = globalThis.fetch,
    sleep = (ms) => new Promise((done) => setTimeout(done, ms)),
  } = {},
) {
  const { values: args } = parseArgs({
    args: argv,
    options: {
      env: { type: 'string' },
      config: { type: 'string', default: 'wrangler.jsonc' },
      'issue-token': { type: 'boolean', default: false },
      rebuild: { type: 'boolean', default: false },
      local: { type: 'boolean', default: false },
    },
  });
  const configPath = resolve(root, args.config);
  const scratch = mkdtempSync(join(tmpdir(), 'clavifer-deploy-'));
  let calls = 0;
  // wrangler with --config (and --env) appended. Every child runs with WRANGLER_LOG_SANITIZE=true,
  // whatever this process or a .env file says (wrangler lets the process environment win over .env):
  // set to false, it makes wrangler write request bodies, the root key among them, to its log file.
  // A failure comes back with the code and message wrangler wrote to its output file. A command
  // whose output is parsed does not print its stderr either: some of its failures are expected (a
  // Worker that does not exist yet, a database never migrated).
  const childEnv = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([name]) => name.toUpperCase() !== 'WRANGLER_LOG_SANITIZE'),
    ),
    WRANGLER_LOG_SANITIZE: 'true',
  };
  const wrangler = (command, { input, parse = false, env = {} } = {}) => {
    const argv = [
      wranglerBin,
      ...command,
      '--config',
      configPath,
      ...(args.env === undefined ? [] : ['--env', args.env]),
    ];
    for (let attempt = 1; ; attempt++) {
      const output = join(scratch, `${++calls}.ndjson`);
      const child = spawn(process.execPath, argv, {
        cwd: root,
        env: { ...childEnv, ...env, WRANGLER_OUTPUT_FILE_PATH: output },
        input,
        encoding: 'utf8',
        stdio: [input === undefined ? 'ignore' : 'pipe', parse ? 'pipe' : 'inherit', parse ? 'pipe' : 'inherit'],
      });
      if (child.status === 0) return { stdout: child.stdout };
      const failed = (existsSync(output) ? readFileSync(output, 'utf8').split('\n').filter(Boolean) : [])
        .map((line) => JSON.parse(line))
        .find((entry) => entry.type === 'command-failed');
      // d1 execute --json reports API errors as JSON text without a code of its own.
      const code = failed?.code ?? Number(/\[code: (\d+)\]/.exec(failed?.message)?.[1]);
      if (attempt === 1 && transient.includes(code)) continue;
      const message =
        failed?.message ?? `exited with status ${child.status}${child.stderr ? `: ${child.stderr.trim()}` : ''}`;
      return { failed: { code, message } };
    }
  };
  const must = (result, what) => {
    if (result.failed) throw new Error(`wrangler ${what} failed: ${result.failed.message}`);
    return result.stdout;
  };
  const query = (sql, where) => wrangler(['d1', 'execute', 'DB', where, '--json', '--command', sql], { parse: true });
  // issueSql takes the token's hash as its one bind, but d1 execute takes no binds; the hash is
  // base64url, which has no quote that could end the literal.
  const issue = async (name, where) => {
    const path = join(root, 'work', `${name}-bootstrap.token`);
    await mkdir(dirname(path), { recursive: true });
    // A new token replaces the instance's earlier one, so an earlier file is useless.
    await rm(path, { force: true });
    const { sql, binds } = await issueToken(path);
    must(query(sql.replace('?', `'${binds[0]}'`), where), 'd1 execute (issue token)');
    console.log(`Bootstrap token written to ${relative(root, path)}; open /setup and enter it there.`);
  };

  try {
    if (args.local) {
      if (args.env !== undefined || args.rebuild || args['issue-token'])
        throw new Error('--local takes only --config: it uses the top-level, local development configuration');
      // A local root key in .dev.vars, beside the configuration, where wrangler dev reads it. An
      // existing file holds the key the local data is encrypted with and is never replaced; one
      // without a ROOT_KEY the Worker accepts is from an older version. No value is ever printed.
      const vars = join(dirname(configPath), '.dev.vars');
      if (existsSync(vars)) {
        const value = /^ROOT_KEY=(.*)$/m.exec(readFileSync(vars, 'utf8'))?.[1].trim();
        try {
          parseRootKeys(value ?? '');
        } catch {
          throw new Error(
            `${relative(root, vars)} has no valid ROOT_KEY: it is from an older version of this project and must be replaced. ` +
              'Deleting it loses the key the local data is encrypted with, so the local database has to start over; then run --local again.',
          );
        }
        console.log(`${relative(root, vars)} already exists with a valid ROOT_KEY; it is left as it is.`);
      } else {
        await writeFile(vars, `ROOT_KEY=${newRootKey()}\n`, { mode: 0o600, flag: 'wx' });
        console.log(`Created ${relative(root, vars)} with a new root key; do not paste it into agent chat or logs.`);
      }
      must(wrangler(['d1', 'migrations', 'apply', 'DB', '--local']), 'd1 migrations apply --local');
      await issue('local', '--local');
      return;
    }

    if (args.env === undefined)
      throw new Error('--env is required: the top level of the configuration is for local development only');
    const env = args.env;
    const config = unstable_readConfig({ config: configPath, env });
    refuseStatic(
      config,
      env,
      (name) => unstable_readConfig({ config: configPath, env: name }, { hideWarnings: true }),
      args.config,
    );
    const own = target(config);
    const host = own.hostname;
    const account = config.account_id;

    // --rebuild replaces the root key, which cannot be undone: only for an instance that says its key
    // is lost or replaced, or whose database was deleted (checked below, once the bindings are known).
    // Any other answer, an outage's 500 included, is no evidence of either.
    const health = args.rebuild ? await (await fetch(`https://${host}/healthz`)).json() : undefined;
    const keyLost = health?.keys === 'mismatch' || health?.error === 'invalid_root_key';

    // Live state, read only.
    const status = wrangler(['deployments', 'status', '--json'], { parse: true });
    let worker = null;
    if (!status.failed || !workerNotFound.includes(status.failed.code)) {
      // Every version of the current deployment: a gradual deployment has more than one.
      const versions = JSON.parse(must(status, 'deployments status')).versions;
      const bindings = versions.flatMap(
        ({ version_id }) =>
          JSON.parse(must(wrangler(['versions', 'view', version_id, '--json'], { parse: true }), 'versions view'))
            .resources.bindings,
      );
      const secrets = JSON.parse(must(wrangler(['secret', 'list'], { parse: true }), 'secret list'));
      // Each D1 and R2 binding as binding=resource, to compare with DB and BACKUPS in the configuration.
      const of = (type, resource) => bindings.filter((b) => b.type === type).map((b) => `${b.name}=${b[resource]}`);
      worker = {
        databases: of('d1', 'database_id'),
        databaseIds: [...new Set(bindings.filter((b) => b.type === 'd1').map((b) => b.database_id))],
        buckets: of('r2_bucket', 'bucket_name'),
        rootKey: secrets.some((s) => s.name === 'ROOT_KEY'),
      };
      // A Worker without D1 or R2 bindings but with ROOT_KEY is the placeholder `wrangler secret put`
      // creates when the Worker does not exist yet: a first run stopped after storing the root key.
      // One without ROOT_KEY is not known to be this entry's, and is refused below.
      worker.placeholder = !worker.databases.length && !worker.buckets.length;
    }

    // The other evidence for --rebuild: every database the deployed versions are bound to is gone. The
    // import brings a snapshot whose values are re-encrypted under the new key, so the old key is not
    // needed. wrangler looks up an id that is not in the configuration through the API and reports a
    // 404 with this message; any other failure stops.
    if (args.rebuild && !keyLost) {
      const ids = worker?.databaseIds ?? [];
      const existing = ids.filter((id) => {
        const info = wrangler(['d1', 'info', id, '--json'], { parse: true });
        if (info.failed?.message.startsWith(`Couldn't find a D1 DB with name or binding '${id}' in your config`))
          return false;
        must(info, 'd1 info');
        return true;
      });
      if (!ids.length || existing.length)
        throw new Error(
          `https://${host}/healthz answers ${JSON.stringify(health)}, not a lost or replaced root key, and ${
            ids.length
              ? `the database ${existing.join(', ')} of the Worker ${config.name} still exists`
              : `the Worker ${config.name} ${worker ? 'has no D1 binding' : 'does not exist'}`
          }; --rebuild is only for an instance whose root key is lost or replaced or whose database was deleted`,
        );
    }

    // wrangler prints the token through its logger, which also writes its log file.
    const auth = JSON.parse(
      must(wrangler(['auth', 'token', '--json'], { parse: true, env: { WRANGLER_WRITE_LOGS: 'false' } }), 'auth token'),
    );
    if (!auth.token)
      throw new Error(
        'wrangler is signed in with CLOUDFLARE_API_KEY and CLOUDFLARE_EMAIL; use an API token or wrangler login',
      );
    const api = async (path) => {
      const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}${path}`, {
        headers: { authorization: `Bearer ${auth.token}` },
      });
      const body = await response.json();
      if (!body.success) throw new Error(`GET ${path} failed: ${JSON.stringify(body.errors)}`);
      return body;
    };
    // Non-interactively, wrangler deploy moves a hostname from another Worker and overwrites an
    // existing DNS record for it without asking. So a hostname that is not this Worker's custom
    // domain must be attached to nothing and resolve to nothing yet.
    const attached = (await api(`/workers/domains?hostname=${encodeURIComponent(host)}`)).result.find(
      (domain) => domain.hostname?.toLowerCase() === host.toLowerCase(),
    );
    let resolves = false;
    if (!attached)
      for (const type of ['A', 'AAAA', 'CNAME']) {
        const response = await fetch(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`,
          { headers: { accept: 'application/dns-json' } },
        );
        const answer = response.ok ? await response.json() : {};
        // 0 is an answer, 3 a name that does not exist; anything else is not known to be free.
        if (![0, 3].includes(answer.Status)) throw new Error(`the DNS lookup of ${host} (${type}) failed`);
        resolves ||= Boolean(answer.Answer?.length);
      }
    const read = query("SELECT 1 FROM system_state WHERE key='owner_user_id'", '--remote');
    // A database that was never migrated has no system_state yet.
    const initialized = read.failed?.message.includes('no such table: system_state')
      ? false
      : JSON.parse(must(read, 'd1 execute (read the instance state)'))[0].results.length > 0;

    // The live state must agree with the configuration; --rebuild may rebind the Worker to the new
    // database only.
    const bound = worker && !worker.placeholder;
    const other = (values, expected) => values.filter((value) => value !== expected);
    if (worker?.placeholder && !worker.rootKey)
      throw new Error(
        `the Worker ${config.name} exists but has neither the D1 and R2 bindings of this configuration nor a ROOT_KEY, so it is not a Clavifer instance of this configuration and deploying would replace it; give the environment another Worker name, or delete that Worker yourself`,
      );
    if (bound && !args.rebuild && other(worker.databases, `DB=${own.database_id}`).length)
      throw new Error(
        `the Worker ${config.name} has the D1 binding ${other(worker.databases, `DB=${own.database_id}`).join(', ')}, not DB=${own.database_id}; deploying would rebind it`,
      );
    if (bound && other(worker.buckets, `BACKUPS=${own['R2 bucket']}`).length)
      throw new Error(
        `the Worker ${config.name} has the R2 binding ${other(worker.buckets, `BACKUPS=${own['R2 bucket']}`).join(', ')}, not BACKUPS=${own['R2 bucket']}; deploying would rebind it`,
      );
    if (attached && attached.service !== config.name)
      throw new Error(
        `${host} is attached to the Worker ${attached.service ?? '(none named)'}; deploying would move it to ${config.name}`,
      );
    if (resolves)
      throw new Error(
        `${host} already resolves in DNS but is not a custom domain of any Worker; deploying would overwrite its DNS record`,
      );
    if (args.rebuild && initialized)
      throw new Error(
        `the database ${own.database_id} is initialized; --rebuild only goes into a new, uninitialized database`,
      );
    if (!bound && initialized)
      throw new Error(
        `the database ${own.database_id} is initialized, but the Worker ${config.name} ${worker ? 'is only a placeholder' : 'does not exist'}; deploying would give its data a new root key`,
      );
    if (bound && !worker.rootKey && initialized)
      throw new Error(
        `the Worker ${config.name} has no ROOT_KEY, but its database is initialized and needs the key it was set up with; if that key is lost, recover with --rebuild into a new database`,
      );

    // A root key for an uninitialized database whose Worker has none; --rebuild replaces the lost one.
    if (args.rebuild || (!initialized && !worker?.rootKey)) {
      // Generated once: a retry of the same call sends the same key.
      must(wrangler(['secret', 'put', 'ROOT_KEY'], { input: newRootKey() }), 'secret put ROOT_KEY');
      console.log('Stored a new ROOT_KEY on the Worker; it exists nowhere else.');
    }

    // wrangler has reported success without applying anything, so d1_migrations is checked against the
    // migrations directory wrangler applies from.
    must(wrangler(['d1', 'migrations', 'apply', 'DB', '--remote']), 'd1 migrations apply');
    const database = config.d1_databases.find((d) => d.binding === 'DB');
    const directory = resolve(dirname(configPath), database.migrations_dir ?? 'migrations');
    const local = readdirSync(directory)
      .filter((file) => file.endsWith('.sql'))
      .sort();
    const applied = JSON.parse(
      must(
        query(`SELECT name FROM ${database.migrations_table ?? 'd1_migrations'} ORDER BY id`, '--remote'),
        'd1 execute (read d1_migrations)',
      ),
    )[0].results.map((row) => row.name);
    if (JSON.stringify(applied) !== JSON.stringify(local))
      throw new Error(
        `the database lists the migrations ${applied.join(', ') || '(none)'}, but ${relative(root, directory)} has ${local.join(', ')}; stopping before deploying`,
      );

    if (spawn('npm run build:web', [], { cwd: root, stdio: 'inherit', shell: true }).status !== 0)
      throw new Error('npm run build:web failed');
    must(wrangler(['deploy']), 'deploy');

    // Before acceptance: the certificate of a new custom domain can take minutes.
    if (!initialized || args['issue-token']) await issue(env, '--remote');

    // Old and new versions answer in turn for a short while, and a new custom domain has no
    // certificate for a few minutes: up to 10 minutes for the answer this deployment must give.
    const expected = { ok: true, version, keys: initialized ? 'ok' : 'uninitialized', initialized };
    let seen;
    for (let attempt = 0; ; attempt++) {
      try {
        const health = await (await fetch(`https://${host}/healthz`)).json();
        seen = JSON.stringify(Object.fromEntries(Object.keys(expected).map((key) => [key, health[key]])));
      } catch (error) {
        seen = error.message;
      }
      if (seen === JSON.stringify(expected)) break;
      if (attempt === 60)
        throw new Error(
          `https://${host}/healthz did not answer ${JSON.stringify(expected)} within 10 minutes; last: ${seen}`,
        );
      await sleep(10000);
    }
    console.log(`https://${host} runs ${version}${initialized ? '' : ', uninitialized'}.`);

    if (args.rebuild) {
      // Keys are vault/<day>/<milliseconds>-<id>.age, so the greatest is the latest. wrangler has no
      // command that lists objects.
      const bucket = own['R2 bucket'];
      let latest, cursor;
      do {
        const page = await api(
          `/r2/buckets/${bucket}/objects?prefix=vault/&per_page=1000${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
        );
        for (const object of page.result) if (!latest || object.key > latest) latest = object.key;
        cursor = page.result_info?.is_truncated ? page.result_info.cursor : undefined;
      } while (cursor);
      console.log(
        latest
          ? `Latest automatic backup: ${latest}\nFetch it with: npx wrangler r2 object get ${bucket}/${latest} --remote --file <path> --config ${args.config} --env ${env}\nthen import it on /setup.`
          : `${bucket} has no automatic backup under vault/.`,
      );
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await deploy(process.argv.slice(2)).catch((error) => {
    console.error(`deploy: ${error.message}`);
    process.exitCode = 1;
  });
