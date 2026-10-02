// Continuous monitoring: turn one-shot checks into a watch that reports how a
// project's security drifts over time. The core (driftReport) is pure and tested;
// the CLI `watch` command (src/cli.js) wraps it around a re-check loop.

// Compare two check results and describe what changed for security.
// prev/curr: { guardScore, verdict, findings:[{id?,class,table}] }
export function driftReport(prev, curr) {
  const key = f => `${f.class}|${f.table}`;
  const prevSet = new Set((prev?.findings || []).map(key));
  const currSet = new Set((curr?.findings || []).map(key));
  const introduced = (curr?.findings || []).filter(f => !prevSet.has(key(f)));
  const resolved = (prev?.findings || []).filter(f => !currSet.has(key(f)));
  const scoreDelta = (curr?.guardScore ?? 0) - (prev?.guardScore ?? 0);
  const regressed = introduced.length > 0 || (curr?.guardScore != null && prev?.guardScore != null && curr.guardScore < prev.guardScore) || (prev?.verdict === 'safe' && curr?.verdict !== 'safe');
  const improved = resolved.length > 0 && introduced.length === 0 && scoreDelta > 0;
  let headline;
  if (regressed) headline = `⚠️ Security regressed: ${introduced.length} new finding(s), Guard Score ${prev?.guardScore ?? 'n/a'} → ${curr?.guardScore ?? 'n/a'}`;
  else if (improved) headline = `✅ Improved: ${resolved.length} finding(s) resolved, Guard Score ${prev?.guardScore ?? 'n/a'} → ${curr?.guardScore ?? 'n/a'}`;
  else headline = `No security change (Guard Score ${curr?.guardScore ?? 'n/a'})`;
  return { changed: regressed || improved, regressed, improved, scoreDelta, introduced, resolved, headline };
}

// Should a re-check run? Only when security-relevant structure changed, so a watch
// doesn't burn a full attack run on every keystroke.
export function shouldRecheck(changedTables) {
  return Array.isArray(changedTables) && changedTables.length > 0;
}
