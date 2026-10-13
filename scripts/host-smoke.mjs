import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { resolve, join, delimiter } from 'node:path';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

// profiles: [codex, claude] names of logged-in CLI profiles; omitted means the in-memory test helper.
export async function hostSmoke(profile, token, profiles) {
  const binary = resolve(profiles ? 'dist/clavifer.exe' : 'work/clavifer-integration.test.exe');
  const bridgeArgs = profiles ? ['--profile', profiles[0], 'mcp'] : ['-test.run=^TestMCPHostHelper$'];
  const env = profiles
    ? process.env
    : {
        ...process.env,
        CLAVIFER_E2E_PROFILE: JSON.stringify(profile),
        CLAVIFER_E2E_TOKEN: JSON.stringify({ ...token, expires_at: Math.floor(Date.now() / 1000) + 600 }),
      };
  // Config contains only a test executable and names of inherited variables.
  // Does not alter either host's saved configuration or start an LLM turn.
  const toml = `mcp_servers={clavifer={command=${JSON.stringify(binary.replaceAll('\\', '/'))},args=${JSON.stringify(bridgeArgs)},startup_timeout_sec=45,env_vars=${profiles ? '["APPDATA","LOCALAPPDATA","USERPROFILE"]' : '["CLAVIFER_E2E_PROFILE","CLAVIFER_E2E_TOKEN"]'}}}`;
  const codex = spawn('codex', ['app-server', '--stdio', '-c', toml], {
    env,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const pending = new Map();
  let next = 1;
  let stderr = '';
  codex.stderr.on('data', (b) => {
    stderr += b.toString();
  });
  codex.on('error', () => {
    for (const item of pending.values()) {
      clearTimeout(item.timer);
      item.reject(new Error('Codex app-server could not start'));
    }
    pending.clear();
  });
  codex.on('exit', (code) => {
    for (const item of pending.values()) {
      clearTimeout(item.timer);
      item.reject(new Error('Codex app-server exited before its reply: ' + code));
    }
    pending.clear();
  });
  const lines = createInterface({ input: codex.stdout });
  lines.on('line', (line) => {
    try {
      const msg = JSON.parse(line);
      if (pending.has(msg.id)) {
        const { resolve, reject, timer } = pending.get(msg.id);
        clearTimeout(timer);
        pending.delete(msg.id);
        msg.error ? reject(new Error('Codex protocol error ' + msg.error.code)) : resolve(msg.result);
      }
    } catch {}
  });
  function rpc(method, params) {
    return new Promise((resolve, reject) => {
      const id = next++;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(
          new Error(
            'Codex ' +
              method +
              ' timed out; loginMissing=' +
              /not logged in/.test(stderr) +
              '; storeUnavailable=' +
              /credentials unavailable/.test(stderr),
          ),
        );
      }, 60000);
      pending.set(id, { resolve, reject, timer });
      codex.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }
  try {
    await rpc('initialize', {
      clientInfo: { name: 'clavifer-acceptance', title: 'Local MCP compatibility test', version: '1' },
      capabilities: { experimentalApi: false, requestAttestation: false },
    });
    codex.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'initialized' }) + '\n');
    const result = await rpc('mcpServerStatus/list', {});
    const server = result.data.find((s) => s.name === 'clavifer');
    assert(server && Object.keys(server.tools).length === 4, 'Codex did not discover four MCP tools');
    console.log('Codex app-server: standard MCP initialization and four tools discovered.');
  } finally {
    lines.close();
    codex.stdin.end();
    codex.kill();
    for (const item of pending.values()) clearTimeout(item.timer);
  }
  // Claude Code on PATH is claude.exe itself (native install) or an npm shim beside the package that holds it.
  const claudeBinary = process.env.PATH.split(delimiter)
    .flatMap((dir) => [join(dir, 'claude.exe'), join(dir, 'node_modules/@anthropic-ai/claude-code/bin/claude.exe')])
    .find((file) => existsSync(file));
  assert(claudeBinary, 'Claude Code was not found on PATH');
  const configDir = resolve('work', 'claude-smoke-' + randomUUID());
  await mkdir(configDir);
  const claudeEnv = { ...env, CLAUDE_CONFIG_DIR: configDir };
  async function claude(args) {
    return new Promise((resolve, reject) => {
      const child = spawn(claudeBinary, args, {
        env: claudeEnv,
        cwd: configDir,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let output = '';
      child.stdout.on('data', (b) => (output += b.toString()));
      child.stderr.on('data', () => {});
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error('Claude MCP health check timed out'));
      }, 30000);
      child.on('error', reject);
      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({ code, output });
      });
    });
  }
  const claudeArgs = profiles ? ['--profile', profiles[1], 'mcp'] : bridgeArgs;
  const added = await claude([
    'mcp',
    'add',
    '--transport',
    'stdio',
    '--scope',
    'user',
    'clavifer',
    '--',
    binary,
    ...claudeArgs,
  ]);
  assert.equal(added.code, 0, 'isolated Claude configuration failed');
  const result = await claude(['mcp', 'list']);
  assert(
    result.code === 0 && /clavifer[^\n]*Connected/i.test(result.output),
    'Claude Code MCP health check did not report Connected',
  );
  console.log('Claude Code: MCP server health check Connected.');
}
