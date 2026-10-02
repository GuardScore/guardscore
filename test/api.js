// The HTTP API a builder platform calls, end to end.
import { makeServer } from '../src/server.js';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const proj = join(root, 'test', 'mcp-project');
const files = {};
for (const f of readdirSync(join(proj, 'supabase', 'migrations'))) files[`supabase/migrations/${f}`] = readFileSync(join(proj, 'supabase', 'migrations', f), 'utf8');
let failures = 0;
const expect = (c, m) => { if (!c) { failures++; console.log(`  FAIL ${m}`); } };

const server = makeServer();
await new Promise(ok => server.listen(0, '127.0.0.1', ok));
const url = `http://127.0.0.1:${server.address().port}`;
const post = async (path, body) => { const r = await fetch(url + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };

expect((await (await fetch(url + '/v1/health')).json()).ok, 'health');
const c = await post('/v1/check', { files });
expect(c.status === 200 && c.body.verdict === 'unsafe', `check verdict unsafe (got ${c.status} ${c.body.verdict || c.body.error})`);
expect(c.body.fixes?.[0]?.proof?.status === 'proven', 'fix comes back proven');
expect(typeof c.body.markdown === 'string' && c.body.markdown.includes('UNSAFE'), 'markdown for a person');
const fix = c.body.fixes.map(f => f.sql).join('\n');
const v = await post('/v1/verify', { files, change_sql: fix });
expect(v.body.verdict === 'safe', `the fix verifies safe (got ${v.body.verdict})`);
const leak = await post('/v1/check', { files: { ...files, 'src/lib/admin.js': "const k = 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ.c2lnbmF0dXJlc2lnbmF0dXJl';" } });
expect(leak.body.findings?.some(f => f.class === 'service_key_exposed'), 'service key in browser code found');
const bad = await post('/v1/check', { files: { '../etc/passwd': 'x' } });
expect(bad.status === 400, 'path escape refused');
const broken = await post('/v1/check', { files: { 'supabase/migrations/1.sql': 'create table (' } });
expect(broken.status === 422, 'bad SQL reported');
server.close();
console.log(failures ? `${failures} failure(s)` : 'api checks passed');
process.exit(failures ? 1 : 0);
