// Talks to the MCP server over stdio exactly as a coding agent would.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { rmSync } from 'node:fs';
import { auditLog } from '../src/receipts.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const project = join(root, 'test', 'mcp-project');
rmSync(join(project, '.verified-changes'), { recursive: true, force: true });
const client = new Client({ name: 'test', version: '1.0.0' });
await client.connect(new StdioClientTransport({ command: 'node', args: [join(root, 'src', 'mcp.js')] }));
let failures = 0;
const expect = (c, m) => { if (!c) { failures++; console.log(`  FAIL ${m}`); } };

const tools = (await client.listTools()).tools.map(t => t.name).sort();
console.log('tools:', tools.join(', '));
expect(tools.join() === 'apply_fixes,check_database,verify_change', 'tool list');

const check = await client.callTool({ name: 'check_database', arguments: { project_dir: project } });
console.log('\ncheck_database ->\n' + check.content[0].text.split('\n').slice(0, 6).join('\n'));
expect(check.structuredContent?.verdict === 'unsafe', 'check verdict unsafe');
expect(check.structuredContent?.findings.some(f => f.class === 'self_grant_admin'), 'finds self-granted admin');

const v = await client.callTool({ name: 'verify_change', arguments: { project_dir: project, change_file: 'supabase/migrations/20260102000000_admin.sql' } });
console.log('\nverify_change (the admin migration) ->\n' + v.content[0].text.split('\n').slice(0, 4).join('\n'));
expect(v.structuredContent?.verdict === 'unsafe', 'verify verdict unsafe');
expect(v.structuredContent?.guardScoreBefore === 100, 'app was safe before the change');
expect(v.structuredContent?.regressions.some(r => r.class === 'self_grant_admin'), 'change blamed for the new hole');

const fixSql = check.structuredContent.fixes.map(f => f.sql).join('\n');
const fixed = await client.callTool({ name: 'verify_change', arguments: { project_dir: project, change_sql: fixSql } });
console.log('\nverify_change (the generated fix) ->\n' + fixed.content[0].text.split('\n').slice(0, 4).join('\n'));
expect(fixed.structuredContent?.verdict === 'safe', 'generated fix makes it safe');

const bad = await client.callTool({ name: 'verify_change', arguments: { project_dir: project, change_sql: 'create table oops (' } });
expect(bad.content[0].text.startsWith('THE CHANGE FAILED TO APPLY'), 'bad SQL reported');

// Declarations need reasons: a bare name or a reason about the check is ignored.
const decl = await client.callTool({ name: 'check_database', arguments: { project_dir: project, public_tables: ['profiles', 'notes: so the check passes'], shared_tables: ['profiles: members see each other\'s names'] } });
const d = decl.structuredContent?.declarations || [];
expect(d.length === 3 && !d[0].honoured && !d[1].honoured && d[2].honoured, 'declarations without a real reason are ignored');
expect(/IGNORED/.test(decl.content[0].text), 'report says which declarations were ignored');

const audit = auditLog(join(project, '.verified-changes'));
console.log(`\nreceipts: ${JSON.stringify(audit)}`);
expect(audit.ok && audit.count === 4, 'four signed receipts, chain valid');

await client.close();
rmSync(join(project, '.verified-changes'), { recursive: true, force: true });
console.log(failures ? `${failures} failure(s)` : 'mcp checks passed');
process.exit(failures ? 1 : 0);
