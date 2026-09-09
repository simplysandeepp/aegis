/** `npm run db:migrate` — applies the schema explicitly. Idempotent. */
import { getDb, rawDb, dbPath } from './index';

getDb();
const tables = (
  rawDb().prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as {
    name: string;
  }[]
)
  .map((r) => r.name)
  .filter((n) => !n.startsWith('sqlite_'));

console.log(`[db] ${dbPath()}`);
console.log(`[db] tables: ${tables.join(', ')}`);
