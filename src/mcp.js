#!/usr/bin/env node
// MCP server: verified changes as native tools a coding agent calls.
//
//   check_database  deep-check a Supabase project's database as it stands
//   verify_change   check a proposed change: verdict after it, what it broke, what it fixed
//
// Both build the database locally from supabase/migrations (no cloud access, no
// real data), add sample data for two users, attack it as an anonymous visitor
// and as another user, confirm real users still work, and return the verdict
// with proof and fixes. Every verdict is signed into a hash-chained receipt log
// in <project>/.verified-changes/.
//
// Add to Claude Code:  claude mcp add verified-changes -- node /path/to/verified-changes/src/mcp.js
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { resolve, join, relative } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { checkApp, verify } from './verify.js';
import { loadProject, writeFixMigration, explainMigrationFailure } from './project-check.js';
import { toStructured as structured } from './formats.js';
import { formatReport } from './report.js';
import { prewarm } from './db.js';

// stdout carries the protocol; anything else goes to stderr.
console.log = (...a) => console.error(...a);

const server = new McpServer({ name: 'verified-changes', version: '0.17.0' });

const common = {
  project_dir: z.string().describe('The Supabase project folder (containing supabase/migrations). Absolute, or relative to where the server was started.'),
  public_tables: z.array(z.string()).optional().describe('Tables meant to be readable by anyone, logged in or not, each as "table: why it is meant to be public" (e.g. "products: the catalog shoppers browse before signing in"). An entry without a reason is ignored and the table is checked as private. Merged with verified-changes.json.'),
  shared_tables: z.array(z.string()).optional().describe('Tables meant to be readable by every signed-in user, each as "table: why" (e.g. "profiles: members see each other\'s names and avatars"). An entry without a reason is ignored. Merged with verified-changes.json.'),
};

const reply = (text, data) => ({ content: [{ type: 'text', text }], structuredContent: data });
const fail = text => ({ content: [{ type: 'text', text }], isError: true });

server.registerTool('check_database', {
  title: 'Check the database',
  description: 'Deep-check a Supabase project\'s database access control as it stands. Builds a private copy from supabase/migrations, fills it with sample data for two users, attacks it as an anonymous visitor and as another user (reading, changing and deleting their rows, impersonating them, joining their team, making yourself admin), and confirms real users can still use their own data. Also checks the app\'s files for a Supabase service-role key reachable from the browser. Returns SAFE, UNSAFE or BREAKS THE APP, with proof for every problem and a fix that has been applied to the copy and re-checked (marked proven) or marked not proven. Run it after changing the database and before telling the user you are done.',
  inputSchema: common,
}, async args => {
  try {
    const p = loadProject(args.project_dir, args);
    if (!p.files.length) return fail('No migrations found. Put the SQL in supabase/migrations/*.sql and check again.');
    const r = await checkApp({ name: 'project', sourceDir: p.dir, manifest: p.manifest, migration: p.sql, seed: '' }, { logDir: join(p.dir, '.verified-changes') });
    return reply(formatReport(r), structured(r));
  } catch (e) {
    return fail(`MIGRATIONS FAILED TO APPLY: ${await explainMigrationFailure(args.project_dir, e).catch(() => e.message)}\nFix that file (or add a new migration after it) and check again.`);
  }
});

server.registerTool('verify_change', {
  title: 'Verify a change',
  description: 'Verify one database change before shipping it. Give either change_file (a migration in the project, which is treated as the change and everything before it as the current app) or change_sql (a change not yet written to a file). Runs the full check before and after, and reports the verdict after the change, anything the change broke (regressions) and anything it fixed.',
  inputSchema: {
    ...common,
    change_file: z.string().optional().describe('Path of the migration file that is the change, relative to project_dir.'),
    change_sql: z.string().optional().describe('SQL of a change not yet written to a migration file.'),
  },
}, async args => {
  if (!args.change_file === !args.change_sql) return fail('Give exactly one of change_file or change_sql.');
  try {
    const p = loadProject(args.project_dir, args, args.change_file);
    const change = args.change_sql ?? readFileSync(resolve(p.dir, args.change_file), 'utf8');
    const app = { name: 'project', sourceDir: p.dir, manifest: p.manifest, migration: p.sql, seed: '' };
    const r = await verify(app, change, { logDir: join(p.dir, '.verified-changes') });
    return reply(formatReport(r, { kind: 'verify' }), r.verdict === 'invalid_change' ? { verdict: r.verdict, error: r.error } : structured(r));
  } catch (e) {
    return fail(`THE CURRENT MIGRATIONS FAILED TO APPLY: ${e.message}\nFix the SQL and verify again.`);
  }
});

server.registerTool('apply_fixes', {
  title: 'Apply the proven fixes',
  description: 'Write every fix the verifier proved on a private copy (the attacks it targets are blocked and real users still work) as the next migration in supabase/migrations, then check the project again with it in place. Use it after check_database reports problems, before fixing anything by hand; then fix only what is left.',
  inputSchema: common,
}, async args => {
  try {
    const f = await writeFixMigration(args.project_dir, { public_tables: args.public_tables, shared_tables: args.shared_tables });
    const head = f.written ? `Wrote ${f.written} with ${f.chosen.length} proven fix(es). The project with it in place:\n\n` : 'No proven fixes to write. The project as it stands:\n\n';
    return reply(head + formatReport(f.after), { written: f.written, applied: f.chosen.map(x => x.table), ...structured(f.after) });
  } catch (e) {
    return fail(`MIGRATIONS FAILED TO APPLY: ${await explainMigrationFailure(args.project_dir, e).catch(() => e.message)}\nFix that file and try again.`);
  }
});

await server.connect(new StdioServerTransport());
// Boot the database engine now, while the agent is still writing SQL, so the
// first check takes a fraction of a second instead of about three.
prewarm();
