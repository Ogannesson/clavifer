export function applyMigrations(
  db: { prepare(sql: string): { run(): Promise<unknown> } },
  directory?: string,
): Promise<void>;
