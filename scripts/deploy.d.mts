import type { spawnSync } from 'node:child_process';

export function deploy(
  argv: string[],
  io?: {
    root?: string;
    spawn?: typeof spawnSync;
    fetch?: typeof globalThis.fetch;
    sleep?: (ms: number) => Promise<void>;
  },
): Promise<void>;
