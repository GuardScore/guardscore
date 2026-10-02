// Real-world projects from public repositories that once got a wrong verdict
// (false alarms from Supabase features the local copy lacked, owners it
// misread) or that hold a real problem the checker must keep finding. Only
// their migrations are kept, for testing; test/corpus is not published.
import { checkProject } from '../src/project-check.js';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = join(dirname(fileURLToPath(import.meta.url)), 'corpus');
const cases = JSON.parse(readFileSync(join(here, 'expected.json'), 'utf8'));
let failures = 0;
for (const c of cases) {
  const r = (await checkProject(join(here, c.case), { log: false })).result;
  if (r.verdict !== c.verdict) { failures++; console.log(`  FAIL ${c.case}: ${r.verdict}, expected ${c.verdict} (${c.why})`); }
}
console.log(failures ? `${failures} corpus case(s) failed` : `corpus checks passed (${cases.length} real-world projects)`);
process.exit(failures ? 1 : 0);
