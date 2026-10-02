// Live mode: a schema dump from a real Postgres (pg_dump 16, with a
// \restrict line and Supabase-style grants), with and without changes made
// outside the migrations.
import { checkProject } from '../src/project-check.js';
import { sanitizeDump } from '../src/live.js';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
let failures = 0;
const expect = (c, m) => { if (!c) { failures++; console.log(`  FAIL ${m}`); } };

const clean = await checkProject(join(here, 'mcp-project'), { log: false, live: { dump: join(here, 'live', 'clean.sql') } });
expect(clean.result.source === 'live' && clean.result.drift.length === 0, `clean dump matches the migrations (drift: ${JSON.stringify(clean.result.drift)})`);

const drifted = await checkProject(join(here, 'mcp-project'), { log: false, live: { dump: join(here, 'live', 'drifted.sql') } });
const items = drifted.result.drift.map(d => d.item);
expect(items.includes('policy "anyone can see profiles" on profiles'), 'dashboard-made policy reported as drift');
expect(items.includes('table feedback'), 'dashboard-made table reported as drift');
expect(drifted.result.findings.some(f => f.table === 'feedback' && f.class === 'anon_read'), 'the live-only table is attacked');
expect(!/\\restrict|set_config\('search_path', ''/.test(sanitizeDump(readFileSync(join(here, 'live', 'drifted.sql'), 'utf8'))), 'dump sanitised');

console.log(failures ? `${failures} failure(s)` : 'live checks passed');
process.exit(failures ? 1 : 0);
