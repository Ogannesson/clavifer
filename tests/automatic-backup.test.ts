import { describe, expect, it, vi } from 'vitest';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { encryptSecret } from '../packages/core/crypto';
import { backupStatus, runAutomaticBackup } from '../apps/worker/src/backup';
import { type Bindings } from '../apps/worker/src/context';

type State = {
  recipient: string | null;
  config_version: number;
  revision: number;
  success_revision: number;
  success_config_version: number;
  success_at: number | null;
  attempt_at: number | null;
  last_error: string | null;
  retention_error: string | null;
  object_key: string | null;
  sha256: string | null;
  lease_token: string | null;
  lease_until: number;
};

async function fixture(options: {
  revision?: number;
  successRevision?: number;
  successConfig?: number;
  successAt?: number | null;
  put?: 'ok' | 'fail' | 'config-change' | 'revision-change';
  commit?: 'ok' | 'lost';
}) {
  const identity = await generateIdentity(),
    recipient = await identityToRecipient(identity);
  const state: State = {
    recipient,
    config_version: 1,
    revision: options.revision ?? 7,
    success_revision: options.successRevision ?? 0,
    success_config_version: options.successConfig ?? -1,
    success_at: options.successAt ?? null,
    attempt_at: null,
    last_error: null,
    retention_error: null,
    object_key: null,
    sha256: null,
    lease_token: null,
    lease_until: 0,
  };
  const key = Buffer.from('c'.repeat(32)).toString('base64url');
  const envelope = await encryptSecret(
    { v1: key },
    'v1',
    { ownerId: 'owner', secretId: 'secret', version: 1 },
    { token: 'synthetic-backup-test' },
  );
  const objects = new Map<string, { data: Uint8Array; uploaded: Date }>();
  let puts = 0;
  const DB = {
    prepare(sql: string) {
      let args: unknown[] = [];
      const statement = {
        bind(...values: unknown[]) {
          args = values;
          return statement;
        },
        async first<T>() {
          if (sql.includes('SELECT * FROM backup_state')) return { ...state } as T;
          if (sql.includes('SELECT value FROM system_state')) return { value: 'owner' } as T;
          throw new Error(`unexpected first: ${sql}`);
        },
        async run() {
          if (sql.startsWith('UPDATE backup_state SET lease_token=')) {
            const [token, until, attempt, config, now, force, oldDaily] = args as [
              string,
              number,
              number,
              number,
              number,
              number,
              number,
            ];
            const eligible =
              state.config_version === config &&
              state.lease_until <= now &&
              (!!force ||
                state.success_revision < state.revision ||
                state.success_config_version !== state.config_version ||
                state.success_at === null ||
                state.success_at <= oldDaily);
            if (eligible) {
              state.lease_token = token;
              state.lease_until = until;
              state.attempt_at = attempt;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }
          if (sql.startsWith('UPDATE backup_state SET success_revision=')) {
            if (options.commit === 'lost') return { meta: { changes: 0 } };
            const [revision, config, at, key, hash, token, expectedConfig] = args as [
              number,
              number,
              number,
              string,
              string,
              string,
              number,
            ];
            if (state.lease_token !== token || state.config_version !== expectedConfig) return { meta: { changes: 0 } };
            state.success_revision = revision;
            state.success_config_version = config;
            state.success_at = at;
            state.object_key = key;
            state.sha256 = hash;
            state.lease_token = null;
            state.lease_until = 0;
            state.last_error = null;
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('UPDATE backup_state SET last_error=')) {
            const [error, token] = args as [string, string];
            if (state.lease_token === token) {
              state.last_error = error;
              state.lease_token = null;
              state.lease_until = 0;
            }
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('UPDATE backup_state SET retention_error=')) {
            state.retention_error = args[0] as string | null;
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('INSERT INTO audit_events')) return { meta: { changes: 1 } };
          throw new Error(`unexpected run: ${sql}`);
        },
      };
      return statement;
    },
    async batch() {
      // This is the same encrypted payload shape used by the Worker, while
      // state and R2 remain externally observable through the assertions below.
      return [
        {
          results: [
            {
              id: 'secret',
              name: 'Synthetic',
              description: '',
              current_version: 1,
              envelope_json: JSON.stringify(envelope),
            },
          ],
        },
        {
          results: [
            {
              id: 'connection',
              name: 'Synthetic',
              origin: 'https://api.example.com',
              auth_json: JSON.stringify({ type: 'bearer', secretId: 'secret', field: 'token' }),
              policy_json: JSON.stringify({ paths: ['/v1'], methods: ['GET'] }),
            },
          ],
        },
        { results: [{ bytes: JSON.stringify(envelope).length }] },
        { results: [{ revision: state.revision }] },
      ];
    },
  };
  const BACKUPS = {
    async put(key: string, data: Uint8Array) {
      puts++;
      if (options.put === 'fail') throw new Error('synthetic R2 unavailable');
      objects.set(key, { data: new Uint8Array(data), uploaded: new Date() });
      if (options.put === 'config-change') {
        state.config_version++;
        state.recipient = await identityToRecipient(await generateIdentity());
      }
      if (options.put === 'revision-change') state.revision++;
      return { key };
    },
    async list({ prefix = '', cursor }: { prefix?: string; cursor?: string } = {}) {
      const keys = [...objects.keys()].filter((key) => key.startsWith(prefix)).sort();
      // Two pages prove the caller follows the cursor instead of reading only the first batch.
      const page = cursor ? keys.slice(1) : keys.slice(0, 1);
      return {
        objects: page.map((key) => ({ key, uploaded: objects.get(key)!.uploaded })),
        ...(cursor || keys.length <= 1 ? { truncated: false } : { truncated: true, cursor: 'next' }),
      };
    },
    async delete(keys: string | string[]) {
      for (const key of Array.isArray(keys) ? keys : [keys]) objects.delete(key);
    },
  };
  const env = {
    DB,
    BACKUPS,
    KEK_RING: `v1:${key}`,
    ACTIVE_KEK_ID: 'v1',
    ALLOW_LOCAL_HTTP: 'false',
  } as unknown as Bindings;
  return { env, state, objects, identity, recipient, puts: () => puts };
}

describe('automatic encrypted backup external outcomes', () => {
  it('stores a new object and publishes success only after R2 upload and DB commit', async () => {
    const f = await fixture({});
    await expect(runAutomaticBackup(f.env, 'owner')).resolves.toMatchObject({ outcome: 'saved', revision: 7 });
    const status = await backupStatus(f.env);
    expect(status).toMatchObject({ savedRevision: 7, pending: false, downloadAvailable: true, lastError: null });
    expect(f.puts()).toBe(1);
    expect(f.objects.size).toBe(1);
  });

  it('keeps the previous known-good state when R2 upload fails', async () => {
    const f = await fixture({ revision: 8, successRevision: 7, successConfig: 1, successAt: Date.now(), put: 'fail' });
    await expect(runAutomaticBackup(f.env, 'owner')).rejects.toMatchObject({ code: 'backup_failed', status: 503 });
    const status = await backupStatus(f.env);
    expect(status).toMatchObject({
      savedRevision: 7,
      pending: true,
      downloadAvailable: false,
      lastError: 'backup_failed',
      running: false,
    });
    expect(f.puts()).toBe(1);
  });

  it('does not publish an object after configuration changes during upload', async () => {
    const f = await fixture({ put: 'config-change' });
    await expect(runAutomaticBackup(f.env, 'owner')).resolves.toEqual({ outcome: 'superseded' });
    const status = await backupStatus(f.env);
    expect(status).toMatchObject({ savedRevision: 0, pending: true, downloadAvailable: false });
    expect(f.objects.size).toBe(1);
  });

  it('retains an uploaded object when the final DB commit is lost', async () => {
    const f = await fixture({ commit: 'lost' });
    await expect(runAutomaticBackup(f.env, 'owner')).resolves.toEqual({ outcome: 'superseded' });
    const status = await backupStatus(f.env);
    expect(status).toMatchObject({ savedRevision: 0, pending: true, downloadAvailable: false, running: true });
    expect(f.objects.size).toBe(1);
  });

  it('leaves savedRevision behind when data changes after snapshot', async () => {
    const f = await fixture({ put: 'revision-change' });
    await expect(runAutomaticBackup(f.env, 'owner')).resolves.toMatchObject({ outcome: 'saved', revision: 7 });
    const status = await backupStatus(f.env);
    expect(status).toMatchObject({ savedRevision: 7, pending: true, downloadAvailable: true });
    expect(status.revision).toBe(8);
  });

  it('keeps the newest copy of every recent day and older month, and never the current one', async () => {
    const f = await fixture({});
    const day = 86400000,
      at = (days: number, hour: number) => {
        const value = new Date(Date.now() - days * day);
        value.setUTCHours(hour, 0, 0, 0);
        return value;
      };
    for (const [key, uploaded] of [
      ['vault/recent-newest', at(2, 12)],
      ['vault/recent-older', at(2, 9)],
      ['vault/month-newest', at(200, 12)],
      ['vault/month-older', at(200, 9)],
      ['vault/expired', at(800, 12)],
    ] as const) {
      f.objects.set(key, { data: new Uint8Array(), uploaded });
    }
    await expect(runAutomaticBackup(f.env, 'owner')).resolves.toMatchObject({ outcome: 'saved' });
    const remaining = [...f.objects.keys()].filter((key) => !key.startsWith('vault/2'));
    expect(remaining.sort()).toEqual(['vault/month-newest', 'vault/recent-newest']);
    expect([...f.objects.keys()].some((key) => key.startsWith('vault/2'))).toBe(true);
    expect(await backupStatus(f.env)).toMatchObject({ retentionError: null, retention: { daily: 30, monthly: 12 } });
  });

  it('reports a failed cleanup without marking the saved backup as failed', async () => {
    const f = await fixture({});
    f.objects.set('vault/stale', { data: new Uint8Array(), uploaded: new Date(Date.now() - 800 * 86400000) });
    f.env.BACKUPS.delete = async () => {
      throw new Error('synthetic R2 delete unavailable');
    };
    await expect(runAutomaticBackup(f.env, 'owner')).resolves.toMatchObject({ outcome: 'saved' });
    expect(await backupStatus(f.env)).toMatchObject({
      savedRevision: 7,
      pending: false,
      lastError: null,
      retentionError: 'backup_retention_failed',
    });
    expect(f.objects.has('vault/stale')).toBe(true);
  });

  it('skips a current backup but runs the daily refresh after 24 hours', async () => {
    const now = Date.now();
    const current = await fixture({ revision: 7, successRevision: 7, successConfig: 1, successAt: now - 60_000 });
    await expect(runAutomaticBackup(current.env, 'owner')).resolves.toEqual({ outcome: 'up_to_date' });
    expect(current.puts()).toBe(0);
    const daily = await fixture({ revision: 7, successRevision: 7, successConfig: 1, successAt: now - 86400001 });
    await expect(runAutomaticBackup(daily.env, 'owner')).resolves.toMatchObject({ outcome: 'saved' });
    expect(daily.puts()).toBe(1);
  });
});
