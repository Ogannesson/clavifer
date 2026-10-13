import { describe, expect, it } from 'vitest';
import { Decrypter, generateIdentity, identityToRecipient } from 'age-encryption';
import { encryptSecret, decryptSecret } from '../packages/core/crypto';
import { exportBackup, restoreBackup } from '../apps/worker/src/backup';
import { authInput } from '../apps/worker/src/vault';
import { type Bindings } from '../apps/worker/src/context';

const owner = 'owner',
  secretId = 'secret';
const key = Buffer.from('b'.repeat(32)).toString('base64url');
type Statement = {
  sql: string;
  args: unknown[];
  bind: (...values: unknown[]) => Statement;
  first: () => Promise<unknown>;
  run: () => Promise<unknown>;
};

async function fixture(auth: ReturnType<typeof authInput.parse>, values: Record<string, string>) {
  const envelope = await encryptSecret({ v1: key }, 'v1', { ownerId: owner, secretId, version: 1 }, values);
  const writes: Statement[] = [];
  const env = {
    KEK_RING: `v1:${key}`,
    ACTIVE_KEK_ID: 'v1',
    ALLOW_LOCAL_HTTP: 'false',
    DB: {
      prepare(sql: string) {
        const statement: Statement = {
          sql,
          args: [],
          bind(...args) {
            statement.args = args;
            return statement;
          },
          async first() {
            return sql.includes(' AS n') ? { n: 0 } : { value: owner };
          },
          async run() {
            return { meta: { changes: 1 } };
          },
        };
        return statement;
      },
      async batch(statements: Statement[]) {
        if (statements[0].sql.startsWith('SELECT s.id'))
          return [
            {
              results: [
                {
                  id: secretId,
                  name: 'Synthetic credential',
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
                  name: 'Synthetic connection',
                  origin: 'https://api.example.com',
                  description: 'Send X-Account: synthetic.',
                  auth_json: JSON.stringify(auth),
                  policy_json: JSON.stringify({
                    paths: ['/v1'],
                    methods: ['GET'],
                    hosts: ['*.files.example.com'],
                    anyHost: true,
                  }),
                },
              ],
            },
            { results: [{ bytes: JSON.stringify(envelope).length }] },
            { results: [{ revision: 7 }] },
          ];
        writes.push(...statements);
        return statements.map(() => ({ meta: { changes: 1 } }));
      },
    },
  } as unknown as Bindings;
  return { env, writes };
}

describe('backup authentication bindings', () => {
  it.each([
    [
      'header',
      authInput.parse({ type: 'header', secretId, field: 'token', name: 'X-API-Key' }),
      { token: 'synthetic\ninvalid-header' },
    ],
    [
      'basic',
      authInput.parse({ type: 'basic', secretId, usernameField: 'username', passwordField: 'password' }),
      { username: 'synthetic:user', password: 'synthetic-password' },
    ],
  ])(
    'preserves recoverable values even when a rotation makes a %s connection unusable',
    async (_label, auth, values) => {
      const { env, writes } = await fixture(auth, values);
      const identity = await generateIdentity(),
        recipient = await identityToRecipient(identity);
      const encrypted = await exportBackup(env, owner, recipient);
      const decrypter = new Decrypter();
      decrypter.addIdentity(identity);
      const snapshot = JSON.parse(await decrypter.decrypt(encrypted, 'text'));
      expect(snapshot.secrets[0].values).toEqual(values);
      expect(snapshot.connections[0].description).toBe('Send X-Account: synthetic.');
      await expect(restoreBackup(env, owner, snapshot)).resolves.toEqual({
        secrets: 1,
        connections: 1,
        requiresNewGrants: true,
      });
      const connectionWrite = writes.find((statement) => statement.sql.startsWith('INSERT INTO connections'))!;
      expect(connectionWrite.args[4]).toBe('Send X-Account: synthetic.');
      // Where else a request may go is part of the connection: it leaves and returns with it.
      const elsewhere = { hosts: ['*.files.example.com'], anyHost: true };
      expect(snapshot.connections[0]).toMatchObject(elsewhere);
      expect(JSON.parse(String(connectionWrite.args[6]))).toMatchObject(elsewhere);
      const versionWrite = writes.find((statement) => statement.sql.startsWith('INSERT INTO secret_versions'))!;
      await expect(
        decryptSecret({ v1: key }, { ownerId: owner, secretId, version: 1 }, JSON.parse(String(versionWrite.args[2]))),
      ).resolves.toEqual(values);
    },
  );

  it('rejects a Basic connection when either required field is missing from the snapshot', async () => {
    const auth = authInput.parse({ type: 'basic', secretId, usernameField: 'username', passwordField: 'password' });
    const { env, writes } = await fixture(auth, { username: 'synthetic-user' });
    const identity = await generateIdentity(),
      recipient = await identityToRecipient(identity);
    await expect(exportBackup(env, owner, recipient)).rejects.toMatchObject({ code: 'backup_has_broken_connection' });
    await expect(
      restoreBackup(env, owner, {
        format: 'agent-credentials-backup-v1',
        createdAt: new Date().toISOString(),
        secrets: [{ id: secretId, name: 'Synthetic', values: { username: 'synthetic-user' } }],
        connections: [{ id: 'connection', name: 'Synthetic', origin: 'https://api.example.com', paths: ['/v1'], auth }],
      }),
    ).rejects.toMatchObject({ code: 'invalid_secret_binding' });
    await expect(
      restoreBackup(env, owner, {
        format: 'agent-credentials-backup-v1',
        createdAt: new Date().toISOString(),
        secrets: [],
        connections: [
          {
            id: 'connection',
            name: 'Synthetic',
            origin: 'https://api.example.com',
            paths: ['/v1'],
            description: 'x'.repeat(2001),
          },
        ],
      }),
    ).rejects.toThrow();
    expect(writes).toEqual([]);
  });
});
