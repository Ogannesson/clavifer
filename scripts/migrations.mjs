import { readFile, readdir } from 'node:fs/promises';
import { unstable_splitSqlQuery } from 'wrangler';

// Share Wrangler's SQL-aware splitter: triggers contain internal semicolons,
// and strings/comments must not be split or stripped with a regular expression.
// Each file is one batch, as wrangler applies a migration: all of it or none.
export async function applyMigrations(db, directory = 'migrations', files) {
  for (const file of files ?? (await readdir(directory)).filter((file) => file.endsWith('.sql')).sort()) {
    const statements = unstable_splitSqlQuery(await readFile(`${directory}/${file}`, 'utf8')).filter((sql) =>
      sql.trim(),
    );
    await db.batch(statements.map((sql) => db.prepare(sql)));
  }
}
