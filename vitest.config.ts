import { defineConfig, configDefaults } from 'vitest/config';

// Agent worktrees keep a full copy of the repository under .claude, which would otherwise be
// collected as a second, stale copy of every test file.
export default defineConfig({
  test: { exclude: [...configDefaults.exclude, '.claude/**'] },
});
