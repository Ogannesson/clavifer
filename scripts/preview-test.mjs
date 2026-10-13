// Local-only, disposable UI acceptance fixture. Never deploy or use real secrets.
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { applyMigrations } from './migrations.mjs';
import { readFile, readdir } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
const origin = 'http://localhost:18878';
const bootstrap = 'synthetic-preview-bootstrap-not-for-real-use';
const assetFiles = new Map();
for (const name of ['index.html', ...(await readdir('apps/web/dist/assets')).map((n) => 'assets/' + n)])
  assetFiles.set('/' + name, await readFile('apps/web/dist/' + name));
const mf = new Miniflare(
  convertV4MiniflareOptions({
    host: '127.0.0.1',
    port: 18878,
    modules: true,
    scriptPath: 'dist/worker/index.js',
    compatibilityDate: '2026-09-11',
    compatibilityFlags: ['nodejs_compat'],
    log: new Log(LogLevel.ERROR),
    d1Databases: ['DB'],
    r2Buckets: ['BACKUPS'],
    serviceBindings: {
      ASSETS: (request) => {
        const path = new URL(request.url).pathname;
        return new Response(assetFiles.get(path) ?? assetFiles.get('/index.html'), {
          headers: {
            'content-type': path.endsWith('.js')
              ? 'application/javascript'
              : path.endsWith('.css')
                ? 'text/css'
                : 'text/html',
          },
        });
      },
    },
    bindings: {
      APP_ORIGIN: origin,
      ALLOW_LOCAL_HTTP: 'true',
      AUTH_SECRET: randomBytes(32).toString('base64url'),
      KEK_RING: `v1:${randomBytes(32).toString('base64url')}`,
      ACTIVE_KEK_ID: 'v1',
      BOOTSTRAP_HASH: createHash('sha256').update(bootstrap).digest('base64url'),
    },
  }),
);
const db = await mf.getD1Database('DB');
await applyMigrations(db);
const response = await mf.dispatchFetch(origin + '/bootstrap', {
  method: 'POST',
  headers: { origin, 'content-type': 'application/json', 'x-bootstrap-token': bootstrap },
  body: JSON.stringify({
    name: 'Preview Owner',
    email: 'preview@example.com',
    password: 'Preview-Only-Not-A-Real-Account!',
  }),
});
if (response.status !== 201) {
  await mf.dispose();
  throw new Error('Preview bootstrap failed: ' + response.status + ' ' + (await response.text()).slice(0, 250));
}
console.log('Disposable UI fixture listening on http://localhost:18878 (synthetic account only).');
for (const event of ['SIGINT', 'SIGTERM'])
  process.on(event, async () => {
    await mf.dispose();
    process.exit(0);
  });
