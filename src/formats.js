// Output formats for platforms: Markdown for a pull-request comment or job
// summary, SARIF for GitHub code scanning (findings show on the lines that
// create the table), and the agent-facing text report lives in report.js.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { FORMAT_VERSION } from './verify.js';

const VERDICT = { safe: 'SAFE', unsafe: 'UNSAFE', breaks_app: 'BREAKS THE APP', incomplete: 'INCOMPLETE', untested: 'UNTESTED', invalid_change: 'CHANGE FAILED TO APPLY' };
const ICON = { safe: '✅', unsafe: '❌', breaks_app: '⚠️', incomplete: '⚠️', untested: '⚠️', invalid_change: '❌' };
const esc = s => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function toMarkdown(r, { kind = 'check' } = {}) {
  const out = [`## ${ICON[r.verdict] || ''} Verified Changes: ${VERDICT[r.verdict] || r.verdict}`];
  if (r.error) return [...out, '', '```', r.error, '```'].join('\n');
  const before = r.guardScoreBefore !== undefined ? `${r.guardScoreBefore} → ` : '';
  out.push('', `Guard Score **${before}${r.guardScore ?? 'n/a'}/100** · ${r.attacks.blocked} of ${r.attacks.run} attacks blocked · ${r.legit.ok} of ${r.legit.run} real-user checks working`);
  out.push('', '_Attacks ran against a private copy built from the migrations, filled with sample data for two users. No real data was touched._');
  if (kind === 'verify' && r.regressions?.length) {
    out.push('', `### This change weakened security (${r.regressions.length})`);
    for (const g of r.regressions) out.push(`- \`${g.id}\`: ${esc(g.proof.actor)} → \`${esc(JSON.stringify(g.proof.observed))}\``);
  }
  if (r.fixes?.length) {
    out.push('', '### Findings and fixes');
    for (const f of r.fixes) {
      const tag = f.proof?.status === 'proven' ? '**fix proven on the copy**' : f.proof?.status === 'code_change' ? 'code change' : '**fix not proven, adapt before use**';
      out.push('', `#### \`${f.table}\` · ${tag}`);
      for (const p of f.problems) out.push(`- ${p}`);
      out.push('', '<details><summary>Proof</summary>', '');
      for (const id of f.findings) {
        const c = (r.checks || []).find(x => x.id === id);
        if (c) out.push(`- ${esc(c.proof.actor)}: \`${esc(c.proof.sql.replace(/\s+/g, ' ').slice(0, 140))}\` → \`${esc(JSON.stringify(c.proof.observed))}\``);
      }
      out.push('', '</details>', '', '<details><summary>Fix</summary>', '', f.prompt.split('\n').slice(1).join('\n\n'), '', '```sql', f.sql, '```', '', `${f.proof?.note || ''}`, '', '</details>');
    }
  }
  if (r.fixCheck) out.push('', `${r.fixCheck.proven} of ${r.fixCheck.total} database fixes proven; with all applied the verdict is **${VERDICT[r.fixCheck.verdictAfterAllFixes] || r.fixCheck.verdictAfterAllFixes}**.`);
  if (r.declarations?.length) {
    out.push('', '### Declared open', '', '| Table | Open to | Reason | Status |', '|---|---|---|---|');
    for (const d of r.declarations) out.push(`| ${esc(d.table)} | ${d.scope === 'public' ? 'anyone' : 'signed-in users'} | ${esc(d.reason || '')} | ${d.honoured ? (d.flags.length ? `honoured; check: ${esc(d.flags.join('; '))}` : 'honoured') : 'ignored (no real reason)'} |`);
  }
  if (r.missed?.length) out.push('', `Not tested: ${r.missed.map(t => `\`${t}\``).join(', ')} (sample rows could not be created).`);
  if (r.advisor?.length) out.push('', `<details><summary>${r.advisor.length} static warnings from Supabase's advisor rules (not proven)</summary>`, '', ...r.advisor.map(w => `- ${w.level} ${w.rule}: ${esc(w.detail)}`), '', '</details>');
  if (r.receipt) out.push('', `Receipt \`${r.receipt.hash.slice(0, 16)}…\` signed.`);
  return out.join('\n');
}

// Where a finding lives in the source: the migration line that creates the
// table, view or function, or the file:line a leaked key was found on.
function locate(dir, files, finding) {
  const m = /^(.+):(\d+)$/.exec(finding.proof?.sql || '');
  if (finding.class === 'service_key_exposed' && m) return { uri: m[1], line: Number(m[2]) };
  const name = finding.table.replace(/^public\./, '');
  const re = new RegExp(`create\\s+(or\\s+replace\\s+)?(table|view|materialized\\s+view|function)\\s+(if\\s+not\\s+exists\\s+)?("?public"?\\.)?"?${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"?\\b`, 'i');
  for (const f of files || []) {
    const p = join(dir, f);
    if (!existsSync(p)) continue;
    const lines = readFileSync(p, 'utf8').split('\n');
    const i = lines.findIndex(l => re.test(l));
    if (i >= 0) return { uri: f, line: i + 1 };
  }
  return { uri: (files || [])[0] || 'supabase/migrations', line: 1 };
}

export function toSarif(r, { dir = '.', files = [], version = '0.4.0' } = {}) {
  const findings = r.findings || [];
  const rules = [...new Set(findings.map(f => f.class))].map(id => ({
    id, name: id, shortDescription: { text: id.replace(/_/g, ' ') },
    defaultConfiguration: { level: id === 'legit' ? 'warning' : 'error' },
  }));
  const results = findings.map(f => {
    const fix = (r.fixes || []).find(x => x.findings.includes(f.id));
    const loc = locate(dir, files, f);
    return {
      ruleId: f.class, level: f.class === 'legit' ? 'warning' : 'error',
      message: { text: `${fix?.problems?.[0] || f.class} Proof: ${f.proof.actor} ran \`${f.proof.sql.replace(/\s+/g, ' ').slice(0, 160)}\` and got ${JSON.stringify(f.proof.observed)}.${fix ? ` Fix (${fix.proof?.status || 'unchecked'}): ${fix.prompt.split('\n').slice(2, 3).join('')}` : ''}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: loc.uri }, region: { startLine: loc.line } } }],
      partialFingerprints: { verifiedChangesId: f.id },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{ tool: { driver: { name: 'verified-changes', version, rules } }, results }],
  };
}

// The machine-readable result for agents and platforms: verdict, counts,
// findings with proof, fixes with their proof status. No row data, ever.
export function toStructured(r) {
  const brief = c => ({ id: c.id, table: c.table, class: c.class, status: c.status, proof: c.proof });
  return {
    format: FORMAT_VERSION,
    verdict: r.verdict,
    guardScore: r.guardScore,
    ...(r.guardScoreBefore !== undefined ? { guardScoreBefore: r.guardScoreBefore } : {}),
    attacks: r.attacks,
    legit: r.legit,
    notTested: r.notTested,
    findings: (r.findings || []).map(brief),
    ...(r.regressions ? { regressions: r.regressions.map(brief), fixedByChange: r.fixedByChange } : {}),
    fixes: (r.fixes || []).map(({ table, problems, prompt, sql, proof }) => ({ table, problems, prompt, sql, proof })),
    fixCheck: r.fixCheck ?? null,
    declarations: r.declarations ?? [],
    advisor: r.advisor ?? null,
    secretWarnings: r.secretWarnings ?? [],
    settings: r.settings ?? [],
    ...(r.source === 'live' ? { source: 'live', drift: r.drift ?? [] } : {}),
    receipt: r.receipt ? { hash: r.receipt.hash } : null,
  };
}

// A self-contained Guard Score dashboard (one HTML file, no external assets):
// the score, the verdict, every finding with its proof, and the notices. Meant
// to be opened by a builder or shared with a teammate.
const hesc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
export function toHtml(r, { app = 'your project' } = {}) {
  const score = r.guardScore == null ? '—' : r.guardScore;
  const hue = r.guardScore == null ? 210 : Math.round(1.2 * r.guardScore); // red→green
  const V = VERDICT[r.verdict] || r.verdict;
  const leaks = (r.findings || []).filter(f => f.status === 'leaked');
  const broken = (r.findings || []).filter(f => f.status === 'broken');
  const notices = r.notices || [];
  const card = (f) => `<div class="f ${f.status}"><div class="ft">${hesc(f.table)} <span class="cls">${hesc(f.class || f.kind)}</span></div>${f.proof?.actor ? `<div class="pa">${hesc(f.proof.actor)}</div>` : ''}${f.proof?.note ? `<div class="pn">${hesc(f.proof.note)}</div>` : ''}${f.proof?.sql ? `<pre>${hesc(String(f.proof.sql).slice(0, 300))}</pre>` : ''}</div>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Guard Score — ${hesc(app)}</title>
<style>
:root{--bg:#0b0e14;--fg:#e6e9ef;--mut:#9aa4b2;--card:#141925;--line:#232a39;--hi:#ff5c6c;--wa:#ffb454;--ok:#54d18c}
@media(prefers-color-scheme:light){:root{--bg:#f6f7f9;--fg:#1a1f2b;--mut:#5a6472;--card:#fff;--line:#e4e8ee}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:24px}
.wrap{max-width:820px;margin:0 auto}h1{font-size:19px;margin:0 0 2px}.sub{color:var(--mut);margin:0 0 20px;font-size:13px}
.top{display:flex;gap:20px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:18px}
.ring{width:96px;height:96px;border-radius:50%;display:grid;place-items:center;flex:0 0 auto;background:conic-gradient(hsl(${hue} 70% 50%) calc(${score === '—' ? 0 : score}*1%),var(--line) 0)}
.ring div{width:76px;height:76px;border-radius:50%;background:var(--card);display:grid;place-items:center;font-size:26px;font-weight:700}
.vd{font-size:22px;font-weight:700}.meta{color:var(--mut);font-size:13px;margin-top:4px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);margin:22px 0 8px}
.f{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--hi);border-radius:10px;padding:12px 14px;margin:8px 0}
.f.broken{border-left-color:var(--wa)}.ft{font-weight:600}.cls{color:var(--mut);font-weight:400;font-size:12px;margin-left:6px}
.pa{color:var(--mut);font-size:13px;margin-top:3px}.pn{font-size:13px;margin-top:4px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;overflow:auto;font-size:12px;margin:8px 0 0;color:var(--mut)}
.notice{border-left-color:var(--mut)}.empty{color:var(--mut);font-style:italic}.foot{color:var(--mut);font-size:12px;margin-top:28px;border-top:1px solid var(--line);padding-top:12px}
</style></head><body><div class="wrap">
<h1>Guard Score — ${hesc(app)}</h1><p class="sub">Attacks run against a private copy built from the migrations, with sample data for two users. No real data is touched.</p>
<div class="top"><div class="ring"><div>${score}</div></div><div><div class="vd">${hesc(V)}</div>
<div class="meta">${r.attacks?.blocked ?? 0} of ${r.attacks?.run ?? 0} attacks blocked · ${r.legit?.ok ?? 0} of ${r.legit?.run ?? 0} real-user checks working${r.missed?.length ? ` · ${r.missed.length} table(s) not fully tested` : ''}</div></div></div>
${leaks.length ? `<h2>Holes found (${leaks.length})</h2>${leaks.map(card).join('')}` : '<h2>Holes found</h2><p class="empty">None — every attack was blocked.</p>'}
${broken.length ? `<h2>Breaks real users (${broken.length})</h2>${broken.map(card).join('')}` : ''}
${notices.length ? `<h2>Notices (${notices.length})</h2>${notices.map(n => `<div class="f notice"><div class="ft">${hesc(n.table)}</div><div class="pn">${hesc(n.note)}</div></div>`).join('')}` : ''}
<p class="foot">Verified Changes ${hesc(r.format || '')} · generated ${new Date().toISOString().slice(0, 10)}</p>
</div></body></html>`;
}
