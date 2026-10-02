// Gather SQL migration/schema files for the generic Postgres engine from the
// common layouts (root, migrations/, db/, sql/, prisma/migrations/**), ordered.
import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export function gatherSql(dir) {
  const out = [];
  const pushFile = p => { try { if (statSync(p).size < 2_000_000) out.push({ p, c: readFileSync(p, 'utf8') }); } catch {} };
  const scanDir = (d, recurse = false) => {
    if (!existsSync(d)) return;
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      let s; try { s = statSync(p); } catch { continue; }
      if (s.isDirectory()) { if (recurse) scanDir(p, true); }
      else if (name.endsWith('.sql')) pushFile(p);
    }
  };
  // root-level *.sql (schema.sql etc.), then common migration dirs
  scanDir(dir, false);
  for (const sub of ['migrations', 'db', 'db/migrations', 'sql', 'database', 'prisma/migrations']) scanDir(join(dir, sub), true);
  // order by path so numbered migrations apply in sequence
  out.sort((a, b) => a.p.localeCompare(b.p));
  const seen = new Set();
  return out.filter(x => (seen.has(x.p) ? false : (seen.add(x.p), true))).map(x => x.c);
}
