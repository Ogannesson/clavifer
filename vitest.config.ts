import { defineConfig, configDefaults } from 'vitest/config';

// Agent worktrees keep a full copy of the repository under .claude, which would otherwise be
// collected as a second, stale copy of every test file. Most tests start miniflare and write
// through its D1 and R2, which on CI's Windows runner takes several times vitest's default limits.
export default defineConfig({
  test: { exclude: [...configDefaults.exclude, '.claude/**'], testTimeout: 60_000, hookTimeout: 60_000 },
});
