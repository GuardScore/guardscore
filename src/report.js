// Plain-text verdict an agent (or person) can act on: the result, the proof,
// and how to fix each problem. Used by the MCP server and the CLI checker.
export function formatReport(r, { kind = 'check' } = {}) {
  const lines = [];
  const gaps = r.notTested?.length
    ? `Not tested: ${r.notTested.join(', ')} (the verifier couldn't fill them with its own sample rows; this is about its private test copy, so don't add test data to your migrations).`
    : '';
  if (r.verdict === 'invalid_change') {
    return `THE CHANGE FAILED TO APPLY: ${r.error}\nFix the SQL and verify again.`;
  }
  if (r.verdict === 'safe') {
    lines.push(`SAFE: all ${r.attacks.run} attacks blocked and all ${r.legit.run} real-user checks pass.`);
  } else if (r.verdict === 'untested') {
    lines.push('UNTESTED: no attack could run, so nothing is proven. Sample rows could not be created for any table.');
  } else if (r.verdict === 'incomplete') {
    lines.push(`INCOMPLETE: all ${r.attacks.run} attacks that ran were blocked, but ${r.missed.join(', ')} could not be tested, so the app is not proven safe.`);
  } else if (r.verdict === 'unsafe') {
    lines.push(`UNSAFE: ${r.attacks.leaked} of ${r.attacks.run} attacks succeeded.`);
  } else {
    lines.push(r.alsoReview?.length
      ? `BREAKS THE APP: ${r.legit.broken} of ${r.legit.run} real-user checks fail, so the app can't run for its users. ${r.alsoReview.length} read-side exposure(s) were also found; fix the breakage first, then re-check them: ${r.alsoReview.join(', ')}.`
      : `BREAKS THE APP: security holds, but ${r.legit.broken} of ${r.legit.run} real-user checks fail.`);
  }
  if (kind === 'verify') {
    lines.push(`Guard Score ${r.guardScoreBefore} -> ${r.guardScore}.`);
    if (r.regressions?.length) lines.push(`This change caused: ${r.regressions.map(x => x.id).join(', ')}.`);
    if (r.fixedByChange?.length) lines.push(`This change fixed: ${r.fixedByChange.join(', ')}.`);
  } else {
    if (r.guardScore != null) lines.push(`Guard Score ${r.guardScore}/100.`);
  }
  for (const f of r.fixes || []) {
    lines.push('', `[${f.table}]`);
    for (const p of f.problems) lines.push(`- ${p}`);
    lines.push('Proof:');
    for (const id of f.findings) {
      const c = r.checks.find(x => x.id === id);
      lines.push(`  ${c.proof.actor}: ${c.proof.sql.replace(/\s+/g, ' ').slice(0, 160)} -> ${JSON.stringify(c.proof.observed)}`);
    }
    lines.push(`How to fix: ${f.prompt.split('\n').slice(1).join(' ')}`);
    lines.push('Reference SQL:', f.sql);
    if (f.proof) lines.push(f.proof.status === 'proven' ? `Fix PROVEN: ${f.proof.note}.`
      : f.proof.status === 'code_change' ? `Fix not provable here: ${f.proof.note}.`
      : `Fix NOT PROVEN, adapt it before using: ${f.proof.note}.`);
  }
  if (r.fixCheck) {
    lines.push('', `Fixes: ${r.fixCheck.proven} of ${r.fixCheck.total} database fixes proven on the private copy; with all of them applied the verdict is ${r.fixCheck.verdictAfterAllFixes.toUpperCase().replace('_', ' ')}.`);
    if (r.fixCheck.proven) lines.push('To write the proven fixes as a migration in one step: the apply_fixes tool, or "verified-changes fix". Then fix by hand only what is left.');
  }
  if (r.verdict === 'unsafe' && (r.findings || []).some(f => f.class !== 'service_key_exposed')) {
    lines.push('', 'Only if a table really is meant to be open: pass it in public_tables as "table: who it is for and why" (or shared_tables for every signed-in user). The reason is recorded in the signed receipt.');
  }
  const decl = r.declarations || [];
  if (decl.length) {
    lines.push('', 'Declared open (recorded in the receipt):');
    for (const d of decl) {
      const head = `- ${d.table} (${d.scope === 'public' ? 'anyone' : 'every signed-in user'})`;
      if (!d.honoured) lines.push(`${head}: IGNORED${!d.reason ? ', no reason given' : d.flags.some(f => /owner-only/.test(f)) ? ` ("${d.reason}" describes data each user sees only for themselves, which is private)` : ` ("${d.reason}" says nothing about who the data is for)`}, so it was checked as private.`);
      else lines.push(`${head}: "${d.reason}"${d.flags.length ? ` (check this: ${d.flags.join('; ')})` : ''}`);
    }
  }
  const seen = new Set();
  for (const n of r.notices || []) {
    if (seen.has(n.table)) continue;
    seen.add(n.table);
    lines.push('', `Notice [${n.table}]: ${n.note}`);
  }
  if ((r.missed || []).length) lines.push('');
  for (const c of (r.checks || []).filter(x => x.kind === 'coverage' && (r.missed || []).includes(x.table))) {
    lines.push(`- ${c.table}: ${c.proof.reason}`);
  }
  if (r.verdict === 'incomplete' || r.verdict === 'untested') {
    lines.push('This is a limit of the verifier\'s test data, not a problem you need to fix. Do not loosen policies, drop checks, add columns or add test data to get these tables tested: that makes the app less safe. Only change something if a signed-in user really can\'t write to the table; otherwise tell the user which tables were not tested.');
  }
  if (r.advisor?.length) {
    lines.push('', `Static warnings from Supabase's Security Advisor rules (not proven by an attack; check each):`);
    for (const w of r.advisor) lines.push(`- ${w.level} ${w.rule}: ${w.detail}`);
  }
  if (r.source === 'live') {
    lines.push('', r.drift?.length
      ? `Checked the LIVE database. It differs from your migrations in ${r.drift.length} place(s); the live version is what was attacked:`
      : 'Checked the LIVE database. It matches your migrations.');
    for (const d of r.drift || []) lines.push(`- ${d.detail}`);
    if (r.drift?.length) lines.push('Put these changes into a migration (or undo them) so the files match what runs.');
  }
  if (r.settings?.length) {
    lines.push('', 'Settings to check (read from your project, not attacked):');
    for (const w of r.settings) lines.push(`- ${w.file}${w.line ? `:${w.line}` : ''} ${w.setting}: ${w.detail}`);
  }
  if (r.secretWarnings?.length) {
    lines.push('', 'Service-role keys in server-side files (not shipped to the browser, but keep them out of git):');
    for (const w of r.secretWarnings) lines.push(`- ${w.detail}`);
  }
  if (gaps) lines.push('', gaps);
  if (r.receipt) lines.push('', `Receipt ${r.receipt.hash.slice(0, 16)}… signed and logged.`);
  return lines.join('\n');
}
