export function applyMigrations<S>(
  db: { prepare(sql: string): S; batch(statements: S[]): Promise<unknown> },
  directory?: string,
  files?: string[],
): Promise<void>;
