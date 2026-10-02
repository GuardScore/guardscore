// End-to-end checks for milestone 1.
//  1. Every seeded app gets its expected verdict and failure classes.
//  2. For every unsafe or broken app, the generated fix, applied as a change,
//     produces a safe verdict with legitimate users still working.
//  3. verify() flags regressions on the secure app and passes a harmless change.
//  4. The receipt log verifies, and tampering with it is detected.
import { readdirSync, readFileSync, writeFileSync, mkdtempSync, copyFileSync, mkdirSync, cpSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { loadApp, checkApp, verify } from '../src/verify.js';
import { auditLog } from '../src/receipts.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const appsDir = join(root, 'apps');
const logDir = mkdtempSync(join(tmpdir(), 'vc-receipts-'));
let failures = 0;
const rows = [];

function expectTrue(cond, msg) {
  if (!cond) { failures++; console.log(`  FAIL ${msg}`); }
}

for (const name of readdirSync(appsDir).sort()) {
  const app = loadApp(join(appsDir, name));
  const exp = app.manifest.expect || {};
  const r = await checkApp(app, { logDir });
  const classes = [...new Set(r.findings.map(f => f.class))];
  console.log(`\n${name}: ${r.verdict}, Guard Score ${r.guardScore}, attacks ${r.attacks.blocked}/${r.attacks.run} blocked, legit ${r.legit.ok}/${r.legit.run} ok, inconclusive ${r.inconclusive}`);
  expectTrue(r.verdict === exp.verdict, `${name}: verdict ${r.verdict}, expected ${exp.verdict}`);
  for (const c of exp.classes || []) expectTrue(classes.includes(c), `${name}: expected finding class ${c}, found [${classes.join(', ')}]`);
  expectTrue(r.inconclusive === 0, `${name}: ${r.inconclusive} inconclusive checks`);

  let fixVerdict = '';
  // Code fixes (moving a key out of the browser) aren't database changes to re-run.
  if (r.verdict !== 'safe' && r.fixes.some(f => f.kind !== 'code')) {
    const fixSql = r.fixes.filter(f => f.kind !== 'code').map(f => f.sql).join('\n');
    const v = await verify(app, fixSql, { logDir });
    fixVerdict = `${v.verdict} (score ${v.guardScore}, legit ${v.legit?.ok}/${v.legit?.run})`;
    console.log(`  after generated fix: ${fixVerdict}${v.error ? ' ' + v.error : ''}`);
    expectTrue(v.verdict === 'safe', `${name}: generated fix gives ${v.verdict}`);
    if (v.findings?.length) for (const f of v.findings) console.log(`    still: ${f.id} ${f.status}`);
  }
  rows.push({ app: name, verdict: r.verdict, score: r.guardScore, classes: classes.join(' '), afterFix: fixVerdict });
}

console.log('\nverify() on changes to the secure app');
const secure = loadApp(join(appsDir, '08_secure'));
const cases = [
  ['regress_policy_true.sql', 'unsafe', true],
  ['disable_rls.sql', 'unsafe', true],
  ['add_column.sql', 'safe', false],
];
for (const [file, expected, expectRegression] of cases) {
  const change = readFileSync(join(appsDir, '08_secure', 'changes', file), 'utf8');
  const v = await verify(secure, change, { logDir });
  console.log(`  ${file}: ${v.verdict}, score ${v.guardScoreBefore} -> ${v.guardScore}, regressions: ${v.regressions.map(r => r.id).join(', ') || 'none'}`);
  expectTrue(v.verdict === expected, `${file}: verdict ${v.verdict}, expected ${expected}`);
  expectTrue((v.regressions.length > 0) === expectRegression, `${file}: regression detection`);
}

console.log('\nreceipts');
const audit = auditLog(logDir);
console.log(`  ${audit.count} receipts, chain and signatures ${audit.ok ? 'valid' : 'INVALID: ' + audit.error}`);
expectTrue(audit.ok && audit.count > 0, 'receipt log should verify');

const tampered = mkdtempSync(join(tmpdir(), 'vc-tamper-'));
cpSync(logDir, tampered, { recursive: true });
const logPath = join(tampered, 'log.jsonl');
const lines = readFileSync(logPath, 'utf8').trim().split('\n');
const first = JSON.parse(lines[0]);
first.payload.verdict = 'safe'; // someone tries to rewrite an unsafe result
lines[0] = JSON.stringify(first);
writeFileSync(logPath, lines.join('\n') + '\n');
const t = auditLog(tampered);
console.log(`  after editing one verdict: ${t.ok ? 'NOT detected' : 'detected (' + t.error + ')'}`);
expectTrue(!t.ok, 'tampering should be detected');

console.log('\nsummary');
console.table(rows);
console.log(failures ? `${failures} check(s) failed` : 'all checks passed');
process.exit(failures ? 1 : 0);
