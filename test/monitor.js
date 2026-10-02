// Continuous-monitoring drift core.
import { driftReport, shouldRecheck } from '../src/monitor.js';

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.log('  FAIL', m); } };

const safe = { guardScore: 100, verdict: 'safe', findings: [] };
const leaked = { guardScore: 35, verdict: 'unsafe', findings: [{ class: 'anon_read', table: 'public.profiles' }] };

// regression: safe -> leaked
let d = driftReport(safe, leaked);
ok(d.regressed && !d.improved && d.introduced.length === 1 && d.scoreDelta === -65, 'detects a regression with the new finding and score drop');
ok(/regressed/i.test(d.headline), 'regression headline');

// improvement: leaked -> safe
d = driftReport(leaked, safe);
ok(d.improved && !d.regressed && d.resolved.length === 1 && d.scoreDelta === 65, 'detects an improvement with the resolved finding');

// steady state
d = driftReport(leaked, leaked);
ok(!d.changed && !d.regressed && !d.improved, 'no change when nothing moved');

// swapped finding (one resolved, one new) counts as regression, not improvement
d = driftReport(leaked, { guardScore: 35, verdict: 'unsafe', findings: [{ class: 'anon_write', table: 'public.orders' }] });
ok(d.regressed && d.introduced.length === 1 && d.resolved.length === 1, 'a swapped finding is a regression');

ok(shouldRecheck(['public.profiles']) === true && shouldRecheck([]) === false, 'recheck only when security-relevant tables changed');

console.log(fail ? `monitor: ${fail} failed` : 'monitor checks passed (continuous-monitoring drift core)');
process.exit(fail ? 1 : 0);
