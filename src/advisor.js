// Optional: Supabase's own Security Advisor rules (the open-source "splinter"
// lints), run on the same private database copy, reported as static warnings
// next to the proven findings. They never change the verdict: that stays
// proof-by-execution. Not bundled; install next to the verifier with
//   git clone --depth 1 https://github.com/supabase/splinter vendor/splinter
// or point VC_SPLINTER_DIR at a splinter checkout. Not shipped with the package:
// the splinter repository carries no license file. (The same lints are in the
// Apache-2.0 supabase/supabase repository; porting from there is the path to bundling.)
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// Rules that fire on nearly every Supabase app and rarely mean a leak; kept out
// of the report so the warnings that remain get read.
const LOW_SIGNAL = new Set(['function_search_path_mutable', 'anon_security_definer_function_executable',
  'authenticated_security_definer_function_executable', 'extension_in_public', 'extension_versions_outdated']);

let cached;
function loadLints() {
  if (cached !== undefined) return cached;
  const dir = [process.env.VC_SPLINTER_DIR && join(process.env.VC_SPLINTER_DIR, 'lints'), join(here, '..', 'vendor', 'splinter', 'lints')]
    .find(d => d && existsSync(d));
  cached = dir ? readdirSync(dir).filter(f => f.endsWith('.sql')).map(f => readFileSync(join(dir, f), 'utf8')).filter(s => /'SECURITY'/.test(s)) : null;
  return cached;
}

export const advisorAvailable = () => !!loadLints();

// Runs inside the caller's database copy; everything it creates is rolled back
// with the check (warm engine) or discarded with the engine (fresh engine).
export async function runAdvisor(db) {
  const lints = loadLints();
  if (!lints) return null;
  const warnings = [];
  if (db.nested) await db.exec('savepoint vc_advisor');
  try {
    await db.exec('create schema if not exists lint;');
    for (const sql of lints) {
      const name = sql.match(/lint\."([^"]+)"/)?.[1];
      if (!name) continue;
      try {
        await db.exec(sql);
        const r = await db.query(`select name, level, detail from lint.${JSON.stringify(name)}`);
        for (const x of r.rows) if (x.level !== 'INFO' && !LOW_SIGNAL.has(x.name)) warnings.push({ rule: x.name, level: x.level, detail: x.detail });
      } catch { /* a rule this engine can't run: skip it */ }
    }
  } finally {
    if (db.nested) await db.exec('rollback to savepoint vc_advisor; release savepoint vc_advisor');
  }
  return warnings;
}
