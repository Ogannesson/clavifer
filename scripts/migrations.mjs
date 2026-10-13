import { readFile, readdir } from 'node:fs/promises';
import { unstable_splitSqlQuery } from 'wrangler';

// Share Wrangler's SQL-aware splitter: triggers contain internal semicolons,
// and strings/comments must not be split or stripped with a regular expression.
export async function applyMigrations(db, directory = 'migrations') {
  for (const file of (await readdir(directory)).filter((file) => file.endsWith('.sql')).sort()) {
    for (const sql of unstable_splitSqlQuery(await readFile(`${directory}/${file}`, 'utf8'))) {
      if (sql.trim()) await db.prepare(sql).run();
    }
  }
}
