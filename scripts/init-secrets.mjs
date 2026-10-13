// Generates the four Worker secrets and the token that initializes the Owner.
//   node scripts/init-secrets.mjs                                  .dev.vars and work/local-bootstrap.token
//   node scripts/init-secrets.mjs --env <name> [--config <path>]   work/<name>.secrets.json and work/<name>-bootstrap.token
// It uploads nothing: the first `wrangler deploy --secrets-file` of the environment does. The values
// exist only in memory and in those files; they are generated after the one child process has
// exited and are never printed.
import { randomBytes, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { access, writeFile, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const names = ['AUTH_SECRET', 'KEK_RING', 'ACTIVE_KEK_ID', 'BOOTSTRAP_HASH'];
const b64 = (n) => randomBytes(n).toString('base64url');
const generate = () => {
  const bootstrap = b64(32);
  return {
    bootstrap,
    secrets: {
      AUTH_SECRET: b64(32),
      KEK_RING: `v1:${b64(32)}`,
      ACTIVE_KEK_ID: 'v1',
      BOOTSTRAP_HASH: createHash('sha256').update(bootstrap).digest('base64url'),
    },
  };
};
const refuseExisting = async (path) => {
  try {
    await access(path, constants.F_OK);
    throw new Error(`${path} already exists; refusing to overwrite`);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
};
const secretFile = { mode: 0o600, flag: 'wx' };

// Which of the four secrets the Worker of this environment already has, or null when the Worker does
// not exist yet. Every other failure throws, because a wrong "none" ends in a deploy that replaces
// KEK_RING.
const deployedSecrets = async (env, config) => {
  const dir = await mkdtemp(join(tmpdir(), 'clavifer-init-'));
  const output = join(dir, 'wrangler.ndjson');
  try {
    const run = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url)),
        'secret',
        'list',
        '--env',
        env,
        ...(config === undefined ? [] : ['--config', config]),
      ],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, WRANGLER_OUTPUT_FILE_PATH: output },
      },
    );
    // Output that is not a JSON list of { name } throws here: a list in a shape this script does not
    // know must not read as "no secrets".
    if (run.status === 0) {
      const listed = JSON.parse(run.stdout);
      if (!listed.every((secret) => typeof secret?.name === 'string'))
        throw new Error('wrangler secret list printed a list this script cannot read; nothing was generated');
      return listed.map((secret) => secret.name).filter((name) => names.includes(name));
    }
    // `secret list` turns the API's "Worker not found" (codes 10007 and 10090) into an error without
    // a code, so the first line of its message is the only thing that tells it from other failures.
    // The output file carries that message as wrangler built it, without terminal formatting.
    const failure = (await readFile(output, 'utf8').catch(() => ''))
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .find((entry) => entry.type === 'command-failed');
    if (new RegExp(`^Worker "[^"\n]+" \\(env: ${env}\\) not found\\.(\n|$)`).test(failure?.message)) return null;
    process.stderr.write(run.stderr);
    throw new Error(
      `wrangler secret list failed, so it is unknown whether env "${env}" already has secrets; nothing was generated`,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
};

const { values: args } = parseArgs({ options: { env: { type: 'string' }, config: { type: 'string' } } });
if (args.env === undefined) {
  if (args.config !== undefined) throw new Error('--config only applies together with --env');
  const path = '.dev.vars';
  await refuseExisting(path);
  const { bootstrap, secrets } = generate();
  await mkdir('work', { recursive: true });
  await writeFile('work/local-bootstrap.token', bootstrap, secretFile);
  await writeFile(
    path,
    Object.entries(secrets)
      .map(([name, value]) => `${name}=${value}\n`)
      .join(''),
    secretFile,
  );
  console.log(
    'Created .dev.vars. Open work/local-bootstrap.token locally to initialize the Owner; do not paste it into agent chat or logs.',
  );
} else {
  const env = args.env;
  // The name becomes part of two file names and of the pattern above.
  if (!/^[\w-]+$/.test(env)) throw new Error('--env takes an environment name of letters, digits, _ and -');
  const secretsPath = `work/${env}.secrets.json`;
  const tokenPath = `work/${env}-bootstrap.token`;
  await refuseExisting(secretsPath);
  await refuseExisting(tokenPath);
  const deployed = await deployedSecrets(env, args.config);
  if (deployed?.length)
    throw new Error(
      `the Worker of env "${env}" already has ${deployed.join(', ')}; refusing to generate new secrets. ` +
        'Deploying a new KEK_RING makes every credential stored in this environment impossible to decrypt.',
    );
  const { bootstrap, secrets } = generate();
  await mkdir('work', { recursive: true });
  await writeFile(tokenPath, bootstrap, secretFile);
  await writeFile(secretsPath, `${JSON.stringify(secrets, null, 2)}\n`, secretFile);
  const config =
    args.config === undefined ? '' : ` --config ${/\s/.test(args.config) ? `"${args.config}"` : args.config}`;
  console.log(
    `Created ${secretsPath} and ${tokenPath}.\n` +
      // A Worker under this name that holds none of the four was not deployed by this procedure.
      (deployed
        ? `A Worker for env "${env}" already exists without these secrets; deploying replaces its code.\n`
        : '') +
      `Next: npx wrangler deploy --env ${env} --secrets-file ${secretsPath}${config}\n` +
      `Do not paste these files into agent chat or logs. KEK_RING cannot be read back once it is on the Worker: store ${secretsPath} in a password manager before deploying.`,
  );
}
