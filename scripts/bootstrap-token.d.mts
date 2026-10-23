export const issueSql: string;
export function newToken(): { token: string; binds: [string] };
export function issueToken(path: string): Promise<{ path: string; sql: string; binds: [string] }>;
