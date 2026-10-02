// One-voice renderer used by every non-Supabase engine.
import { renderResult, renderLine } from '../src/render.js';

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.log('  FAIL', m); } };

const unsafe = {
  stack: 'postgres', verdict: 'unsafe', guardScore: 51, identityGuc: 'app.user_id',
  counts: { critical: 2, high: 0, warning: 0 },
  findings: [{ severity: 'critical', table: 'public.notes', class: 'cross_user_read', what: 'One user can read another user’s rows.', fix: 'alter table notes enable row level security;\ncreate policy ...', proof: { actor: 'user A', op: 'select notes where user_id=B', observed: 'read 1 of user B’s row(s)' } }],
};
const txt = renderResult(unsafe);
ok(/Guard Score 51\/100 · UNSAFE · Postgres\/RLS/.test(txt), 'header: score + verdict + stack');
ok(/identity: current_setting\('app\.user_id'\)/.test(txt), 'header carries the identity GUC');
ok(/\[critical\] public\.notes  cross_user_read/.test(txt), 'finding line: severity + table + class');
ok(/proof: user A select notes where user_id=B → read 1 of user B/.test(txt), 'proof receipt rendered consistently');
ok(/fix: alter table notes enable row level security;/.test(txt) && /policy \.\.\./.test(txt), 'multi-line fix rendered');

const safe = { stack: 'postgres', verdict: 'safe', guardScore: 100, counts: {}, findings: [] };
ok(/✅ Guard Score 100\/100 · SAFE/.test(renderResult(safe)) && /No holes/.test(renderResult(safe)), 'safe result → clean headline + reassurance line');

const fb = { stack: 'firebase', verdict: 'unsafe', guardScore: 43, attacks: { run: 6, blocked: 3 }, legit: { run: 2, ok: 2 }, counts: { critical: 3, high: 0, warning: 0 }, findings: [{ severity: 'critical', table: '/users', class: 'anon_read', what: 'x', proof: { actor: 'anon', op: 'get users/victim', observed: 'read succeeded' } }] };
ok(/Firebase · 3\/6 attacks blocked · 2\/2 owner checks OK/.test(renderResult(fb)), 'firebase subtitle: attacks + owner checks');

ok(JSON.parse(renderResult(safe, { format: 'json' })).guardScore === 100, 'json format round-trips');
ok(/Guard Score 51\/100 · UNSAFE · Postgres\/RLS · 1 finding/.test(renderLine(unsafe)), 'one-line summary for CI');

console.log(fail ? `render: ${fail} failed` : 'render checks passed (one-voice renderer)');
process.exit(fail ? 1 : 0);
