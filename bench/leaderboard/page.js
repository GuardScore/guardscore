#!/usr/bin/env node
// Build the public leaderboard page from leaderboard.json.
//   node bench/leaderboard/page.js [out/leaderboard.json] [out/index.html]
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const src = process.argv[2] || join(HERE, 'out', 'leaderboard.json');
const dest = process.argv[3] || join(HERE, 'out', 'index.html');
const data = JSON.parse(readFileSync(src, 'utf8'));
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const pct = x => `${Math.round(100 * x)}%`;

const CLASS = {
  anon_read: 'visitor reads private rows', anon_write: 'visitor changes rows', cross_user_read: 'user reads others\' rows',
  cross_user_write: 'user changes others\' rows', cross_tenant_read: 'reads another team\'s data', impersonated_insert: 'writes as someone else',
  self_grant_admin: 'makes self admin', tenant_self_join: 'joins another team', view_bypass: 'view skips row security',
  token_enumeration: 'lists every share link', rpc_leak: 'function returns others\' data', privileged_tamper: 'edits price or paid status',
  team_self_promotion: 'promotes self in team', public_secret: 'secrets in a public table', declared_sensitive: 'personal data exposed',
  service_key_exposed: 'admin key in browser', storage_read: 'reads others\' files', storage_write: 'deletes others\' files', storage_upload: 'uploads where it shouldn\'t', trusts_user_metadata: 'trusts user-editable metadata',
};

function row(e, rank) {
  const seg = (n, cls, label) => n ? `<span class="seg ${cls}" style="flex:${n}" title="${label}: ${n} of ${e.runs}"></span>` : '';
  const [lo, hi] = e.safe_ci;
  const top = e.leak_classes.slice(0, 3).map(([c, n]) => `<span class="chip">${esc(CLASS[c] || c)} <b>${n}</b></span>`).join('');
  return `<li class="entry">
    <div class="rank">${rank ?? ''}</div>
    <div class="who"><div class="name">${esc(e.label)}</div><div class="meta">${e.runs} sessions · ${e.tasks} apps${e.median_seconds_per_request != null ? ` · ${e.median_seconds_per_request}s per request` : ''}${e.cost_per_run_usd != null ? ` · $${e.cost_per_run_usd.toFixed(2)} per session` : ''}</div></div>
    <div class="score"><div class="big">${pct(e.safe_rate)}</div><div class="ci">95% CI ${pct(lo)}–${pct(hi)}</div></div>
    <div class="bars">
      <div class="stack" role="img" aria-label="${e.safe_and_working} safe and working, ${e.leaks} leak, ${e.breaks} break the app, ${e.other} other">${seg(e.safe_and_working, 'ok', 'Safe and working')}${seg(e.leaks, 'leak', 'Leaks data')}${seg(e.breaks, 'brk', 'Broken')}${seg(e.other, 'oth', 'Not scorable')}</div>
      <div class="whisker"><span style="left:${100 * lo}%;width:${100 * (hi - lo)}%"></span><i style="left:${100 * e.safe_rate}%"></i></div>
      <div class="counts"><span class="k ok">${e.safe_and_working} safe</span><span class="k leak">${e.leaks} leak</span><span class="k brk">${e.breaks} broken${e.migrations_fail ? ` (${e.migrations_fail} won't deploy)` : ''}</span><span class="k oth">${e.other} other</span></div>
      ${top ? `<div class="chips">${top}</div>` : ''}
    </div>
  </li>`;
}

const agents = data.entries.filter(e => !e.verifier);
const assisted = data.entries.filter(e => e.verifier);
const tasks = data.tasks;
const OUT = { safe_and_working: ['ok', 'Safe'], leaks: ['leak', 'Leak'], breaks: ['brk', 'Breaks'], other: ['oth', '—'] };
const matrix = `<div class="scroll"><table class="matrix"><thead><tr><th>App request</th>${data.entries.map(e => `<th>${esc(e.label.replace(/^Claude Code · /, ''))}</th>`).join('')}</tr></thead><tbody>
${tasks.map(t => `<tr><th><span class="tid">${esc(t.id)}</span><span class="tq">“${esc(t.steps[0])}”${t.steps.length > 1 ? ` + ${t.steps.length - 1} follow-ups` : ''}</span></th>${data.entries.map(e => `<td>${(e.per_task[t.id] || []).map(o => `<span class="dot ${OUT[o][0]}" title="${OUT[o][1]}"></span>`).join('')}</td>`).join('')}</tr>`).join('\n')}
</tbody></table></div>`;

const html = `<title>Agent Security Leaderboard</title>
<meta name="description" content="How often coding agents ship a Supabase app that is safe and still works, scored by attacking a private copy of each app.">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans+Condensed:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>
:root{--bg:#f5f6f3;--surface:#fff;--ink:#15191d;--muted:#5d6560;--line:#dde1dc;--accent:#1d5c57;--ok:#2e7d4f;--leak:#b3372c;--brk:#c07a12;--oth:#a3aaa5;--chipbg:#eceee9;
--disp:"IBM Plex Sans Condensed","Arial Narrow",sans-serif;--body:"IBM Plex Sans",system-ui,sans-serif;--mono:"IBM Plex Mono",ui-monospace,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121513;--surface:#1a1e1c;--ink:#e7ebe7;--muted:#9aa39d;--line:#2c322f;--accent:#6fc0b6;--ok:#58b47c;--leak:#e0685c;--brk:#e0a23f;--oth:#5f6763;--chipbg:#242a27;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#121513;--surface:#1a1e1c;--ink:#e7ebe7;--muted:#9aa39d;--line:#2c322f;--accent:#6fc0b6;--ok:#58b47c;--leak:#e0685c;--brk:#e0a23f;--oth:#5f6763;--chipbg:#242a27;color-scheme:dark}
body{background:var(--bg);color:var(--ink);font:15px/1.55 var(--body);padding:40px 20px 64px}
.wrap{max-width:1040px;margin:0 auto;display:grid;gap:44px}
header{display:grid;gap:14px;max-width:72ch}
.eyebrow{font:500 12px/1 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--accent)}
h1{font:700 clamp(34px,6vw,58px)/1.02 var(--disp);letter-spacing:-.01em;margin:0;text-wrap:balance}
h2{font:700 24px/1.15 var(--disp);margin:0 0 6px;text-wrap:balance}
p{margin:0}.lede{font-size:17px;color:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:8px 18px;font-size:13px;color:var(--muted)}
.legend span::before{content:"";display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px;background:var(--c)}
.board{list-style:none;margin:0;padding:0;border-top:2px solid var(--ink)}
.entry{display:grid;grid-template-columns:40px minmax(0,1.3fr) 120px minmax(0,2fr);gap:18px;align-items:start;padding:20px 0;border-bottom:1px solid var(--line)}
.rank{font:700 28px/1 var(--disp);color:var(--muted);font-variant-numeric:tabular-nums}
.name{font-weight:600;font-size:16px}.meta{font:12px/1.5 var(--mono);color:var(--muted);margin-top:4px}
.big{font:700 34px/1 var(--disp);font-variant-numeric:tabular-nums}.ci{font:12px var(--mono);color:var(--muted);margin-top:4px}
.bars{display:grid;gap:7px}
.stack{display:flex;height:14px;border-radius:3px;overflow:hidden;gap:2px;background:var(--line)}
.seg.ok{background:var(--ok)}.seg.leak{background:var(--leak)}.seg.brk{background:var(--brk)}.seg.oth{background:var(--oth)}
.whisker{position:relative;height:8px}.whisker span{position:absolute;top:3px;height:2px;background:var(--ink);opacity:.45}
.whisker i{position:absolute;top:0;width:2px;height:8px;background:var(--ink);margin-left:-1px}
.counts{display:flex;flex-wrap:wrap;gap:4px 14px;font:12px var(--mono);font-variant-numeric:tabular-nums}
.k.ok{color:var(--ok)}.k.leak{color:var(--leak)}.k.brk{color:var(--brk)}.k.oth{color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{font-size:12px;background:var(--chipbg);border-radius:3px;padding:2px 7px;color:var(--muted)}.chip b{color:var(--leak);font-weight:600}
.assist .entry{grid-template-columns:40px minmax(0,1.3fr) 120px minmax(0,2fr)}
.note{font-size:13px;color:var(--muted);max-width:72ch;margin-top:10px}
.scroll{overflow-x:auto;border-top:2px solid var(--ink)}
.matrix{border-collapse:collapse;width:100%;min-width:640px;font-size:13px}
.matrix th,.matrix td{border-bottom:1px solid var(--line);padding:10px 10px 10px 0;text-align:left;vertical-align:top}
.matrix thead th{font:500 11px/1.3 var(--mono);text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.tid{display:block;font:500 12px/1.4 var(--mono)}.tq{display:block;color:var(--muted);font-weight:400;max-width:42ch}
.dot{display:inline-block;width:12px;height:12px;border-radius:50%;margin:2px 4px 0 0}
.dot.ok{background:var(--ok)}.dot.leak{background:var(--leak)}.dot.brk{background:var(--brk)}.dot.oth{background:var(--oth)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:28px}
.cols h3{font:700 17px/1.2 var(--disp);margin:0 0 8px}.cols p,.cols li{font-size:14px;color:var(--muted)}.cols ul{margin:0;padding-left:18px;display:grid;gap:6px}
code{font:13px var(--mono);background:var(--chipbg);padding:1px 5px;border-radius:3px;color:var(--ink)}
pre{font:13px/1.5 var(--mono);background:var(--surface);border:1px solid var(--line);border-radius:4px;padding:12px 14px;overflow-x:auto;margin:8px 0 0}
footer{font:12px var(--mono);color:var(--muted);border-top:1px solid var(--line);padding-top:14px}
@media (max-width:720px){.entry,.assist .entry{grid-template-columns:32px minmax(0,1fr) auto}.bars{grid-column:1/-1}.big{font-size:28px}}
</style>
<div class="wrap">
<header>
  <div class="eyebrow">Supabase apps · ${data.entries.reduce((a, e) => a + e.runs, 0)} build sessions scored</div>
  <h1>Which coding agent ships an app that is safe and still works?</h1>
  <p class="lede">Each agent gets the same vague requests a non-programmer would type, like “build me a journaling app”, with no security hints. Then we build a private copy of the database it wrote, fill it with two users, and attack it: an anonymous visitor and a second user try to read, change and delete the first user's data. The score is the share of sessions where every attack failed and real users could still use the app.</p>
  <div class="legend"><span style="--c:var(--ok)">Safe and working</span><span style="--c:var(--leak)">Leaks data (proved by an attack)</span><span style="--c:var(--brk)">Broken (users locked out, or the database migrations fail)</span><span style="--c:var(--oth)">Not scorable</span></div>
</header>

<section>
  <h2>Agents on their own</h2>
  <ol class="board">${agents.map((e, i) => row(e, i + 1)).join('')}</ol>
  ${new Set(agents.map(e => e.label.split(' · ')[0])).size < 2 ? '<p class="note">One coding agent measured so far. The runner has adapters for Codex CLI, Gemini CLI, Aider and Cursor CLI; results appear here as they are run with the same tasks and the same frozen checker.</p>' : ''}
</section>

${assisted.length ? `<section class="assist">
  <h2>The same agent with a verifier in the loop</h2>
  <p class="note">Same tasks and model, with Verified Changes available to the agent. These rows are not ranked against the agents above; they show how much of the gap a verifier closes. The agent was told the verifier exists; whether it calls it is up to the agent. These sessions ran with v0.7 in the loop (the team app with v0.8) and are scored by the current checker (v${data.checker?.version ?? ''}). The platform row adds a check by the builder's platform after every request.${data.note ? ' ' + esc(data.note) : ''}</p>
  <ol class="board">${assisted.map(e => row(e, '')).join('')}</ol>
</section>` : ''}

<section>
  <h2>Every session, by app</h2>
  <p class="note" style="margin-bottom:14px">One dot per session, colored by the verdict after the last request. Multi-step apps add features one request at a time, the way people build.</p>
  ${matrix}
</section>

<section class="cols">
  <div><h3>How a session is scored</h3><ul>
    <li>The database is rebuilt from the agent's own migration files. Nothing runs against a real project.</li>
    <li>An attack counts only when it succeeds: rows were read or changed that the attacker shouldn't reach. Warnings don't count.</li>
    <li>Real-user checks confirm the owner can still read and edit their own data. An app that blocks everyone isn't safe, it's broken. So is one whose migrations fail to apply.</li>
    <li>Tables meant to be public (a product catalog) are declared per task by us, never by the agent.</li>
  </ul></div>
  <div><h3>What the error bars mean</h3><p>The line under each bar is a 95% Wilson interval for the safe-and-working rate. With about 20 sessions per agent, two agents whose intervals overlap may not really differ. Rankings will firm up as more sessions are run.</p></div>
  <div><h3>Add an agent</h3><p>Run the same tasks and score them with the same checker:</p>
<pre>bench/leaderboard/run.sh codex 3
node bench/leaderboard/score.js
node bench/leaderboard/page.js</pre></div>
</section>

<footer>Checker ${esc(data.checker.version)} · fingerprint ${esc(data.checker.fingerprint)} · generated ${esc(data.generated.slice(0, 10))}. The same checker code gives the same scores.</footer>
</div>`;
writeFileSync(dest, html);
console.log(`written ${dest}`);
