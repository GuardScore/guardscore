// One voice for every engine. Firebase, Postgres, secrets and Prisma all return
// the same result shape ({ stack, verdict, guardScore, findings:[{severity, table,
// class, what, fix, proof? }], counts, ... }); this renders them identically so the
// product reads as one tool, in text (for humans/CI) or JSON (for machines).
// The Supabase deep engine keeps its own richer report (declarations, advisor,
// fix-proof status); this aligns the header wording with it.

const VERDICT = { safe: 'SAFE', unsafe: 'UNSAFE', breaks_app: 'BREAKS THE APP', review: 'REVIEW', clear: 'CLEAR', untested: 'UNTESTED', empty: 'NOTHING TO CHECK' };
const ICON = { safe: '✅', unsafe: '❌', breaks_app: '⚠️', review: '⚠️', clear: '○', untested: '·', empty: '·' };
const STACK = { firebase: 'Firebase', postgres: 'Postgres/RLS', secrets: 'Secrets', prisma: 'Prisma' };

function subtitle(r) {
  const bits = [];
  if (r.stack === 'postgres' && r.identityGuc) bits.push(`identity: current_setting('${r.identityGuc}')`);
  if (r.stack === 'firebase' && r.attacks) bits.push(`${r.attacks.blocked}/${r.attacks.run} attacks blocked`);
  if (r.stack === 'firebase' && r.legit) bits.push(`${r.legit.ok}/${r.legit.run} owner checks OK`);
  if (r.stack === 'prisma' && r.modelCount != null) bits.push(`${r.modelCount} models`);
  if (r.stack === 'secrets' && r.filesScanned != null) bits.push(`${r.filesScanned} files scanned`);
  return bits.join(' · ');
}

function chips(c = {}) {
  const out = [];
  if (c.critical) out.push(`${c.critical} critical`);
  if (c.high) out.push(`${c.high} high`);
  if (c.warning) out.push(`${c.warning} to review`);
  return out.length ? `   ${out.join(' · ')}` : '';
}

// One finding block, consistent across engines: severity, location, plain-English
// what, the proof receipt (who did what and what happened), and the fix.
function finding(f, { showFix = true } = {}) {
  const lines = [`  [${f.severity}] ${f.table}${f.class ? `  ${f.class}` : ''}`];
  if (f.what) lines.push(`      ${f.what}`);
  if (f.proof && f.proof.observed) lines.push(`      proof: ${f.proof.actor ? f.proof.actor + ' ' : ''}${f.proof.op ? f.proof.op + ' → ' : ''}${f.proof.observed}`);
  if (showFix && f.fix) {
    const fx = String(f.fix).split('\n');
    lines.push(`      fix: ${fx[0]}`, ...fx.slice(1).map(l => `           ${l}`));
  }
  return lines.join('\n');
}

export function renderResult(r, { format = 'text', showFix = true } = {}) {
  if (format === 'json') return JSON.stringify(r, null, 2);
  const st = STACK[r.stack] || (r.stack ? r.stack[0].toUpperCase() + r.stack.slice(1) : 'Guard Score');
  const sub = subtitle(r);
  const head = `${ICON[r.verdict] || ''} Guard Score ${r.guardScore ?? 'n/a'}/100 · ${VERDICT[r.verdict] || String(r.verdict).toUpperCase()} · ${st}${sub ? ' · ' + sub : ''}`.trim();
  const out = [head];
  const ch = chips(r.counts);
  if (ch) out.push(ch);
  const findings = r.findings || [];
  if (!findings.length) out.push(r.verdict === 'safe' ? '   No holes — every attack was blocked and legitimate use still works.' : r.verdict === 'clear' ? '   No obvious holes found.' : '   Nothing to report.');
  else { out.push(''); for (const f of findings) out.push(finding(f, { showFix })); }
  if (r.note) out.push('', `note: ${r.note}`);
  return out.join('\n');
}

// One-line summary for logs / CI status lines.
export function renderLine(r) {
  return `Guard Score ${r.guardScore ?? 'n/a'}/100 · ${VERDICT[r.verdict] || r.verdict} · ${STACK[r.stack] || r.stack}${(r.findings || []).length ? ` · ${r.findings.length} finding(s)` : ''}`;
}
