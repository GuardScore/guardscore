// Instant, in-browser static pre-check for Firebase — the Firestore engine's
// front-door scan, a sibling to web/scan.js (Supabase). Same contract:
// read the rules as text, flag only what is unmistakable, UNDER-report rather
// than false-alarm, and hand everything that needs a live attack to the full
// engine (which, for Firebase, is the emulator-based engine specced separately).
//
// It reuses the wording and category logic of src/firebase.js so the fast scan
// and the deep scan never contradict (kept in sync by test/web-firebase-scan.js).

export const EXPLAIN = {
  open_write: 'Anyone on the internet, without signing in, can create, change, or delete documents here (allow write: if true).',
  open_read: 'Anyone on the internet, without signing in, can read every document here (allow read: if true).',
  any_signed_in_write: 'Any signed-in user can write documents here — the rule checks that someone is logged in, not that the document is theirs, so one user can overwrite another’s.',
  rules_missing: 'No Firestore security rules were found, or they are in locked/test mode. Test mode leaves the whole database open to anyone until a set date.',
};
const FIX = {
  open_write: p => `Scope writes to the document’s owner:\n  match ${p} {\n    allow write: if request.auth != null && request.auth.uid == resource.data.uid;\n  }`,
  open_read: p => `Scope reads to the owner (or a membership check):\n  match ${p} {\n    allow read: if request.auth != null && request.auth.uid == resource.data.uid;\n  }`,
  any_signed_in_write: p => `Add an owner check to the write rule:\n  allow write: if request.auth != null && request.auth.uid == resource.data.uid;`,
};

// Paths whose exposure to anonymous readers is a leak by any reading — never a
// public catalog. Keeps an open-read on a personal collection from being
// dismissed as intended.
const SENSITIVE_PATH = /(^|\/)(users?|profiles?|accounts?|members?|messages?|chats?|conversations?|dms?|emails?|payments?|orders?|invoices?|subscriptions?|billing|private|secrets?|tokens?|notes?|journal|documents?|files?|health|medical)($|s?\/|\/)/i;
const OPEN = /^\(?\s*true\s*\)?$/i;
const OWNER = /request\.auth\.uid\s*==|==\s*request\.auth\.uid|resource\.data\.\w*(uid|user|owner|author)\w*\s*==\s*request\.auth\.uid/i;
const AUTHED = /request\.auth\s*!=\s*null|request\.auth\.uid|request\.auth\s*\.\s*token/;
const GATED = /get\s*\(|exists\s*\(|hasrole|has_role|role\s*==|admin|allow_any_operation|isadmin/i;

// Split a rules file into `match <path> { ... }` blocks with their allow lines.
function parseRules(text) {
  const clean = String(text || '').replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
  const blocks = [];
  const re = /match\s+(\S+)\s+\{/g;
  let m;
  while ((m = re.exec(clean))) {
    const start = re.lastIndex;
    const rest = clean.slice(start);
    const end = rest.search(/\bmatch\b|\}/);
    const body = rest.slice(0, end < 0 ? rest.length : end);
    const allows = [...body.matchAll(/allow\s+([a-z,\s]+?)\s*:\s*if\s+([^;]+);/gi)]
      .map(a => ({ ops: a[1].replace(/\s/g, '').split(',').filter(Boolean), cond: a[2].trim().replace(/\s+/g, ' ') }));
    blocks.push({ path: m[1].trim(), allows });
  }
  return blocks;
}

export function firestoreScan(rulesText) {
  const text = String(rulesText || '');
  const blocks = parseRules(text);
  const findings = [];
  const add = (severity, cls, path, what, fix) => findings.push({ severity, class: cls, table: path, what, fix });

  // Test mode / locked mode with a wide-open rule.
  if (/allow\s+read,\s*write\s*:\s*if\s+(true|request\.time\s*<)/i.test(text) && !blocks.some(b => b.allows.length > 1)) {
    // handled per-block below; this is a hint only
  }

  const total = blocks.reduce((n, b) => n + b.allows.length, 0);
  for (const b of blocks) {
    const path = b.path;
    for (const { ops, cond } of b.allows) {
      const write = ops.some(o => /^(write|create|update|delete)$/.test(o));
      const read = ops.some(o => /^(read|get|list)$/.test(o));
      if (OPEN.test(cond)) {
        if (write) add('critical', 'open_write', path, EXPLAIN.open_write, FIX.open_write(path));
        if (read) SENSITIVE_PATH.test(path)
          ? add('critical', 'open_read', path, 'Anyone, without signing in, can read every document here — and the path looks like personal data.', FIX.open_read(path))
          : add('warning', 'open_read', path, 'This path looks readable by anyone without signing in. Fine for public content, a leak otherwise — the full engine confirms by attacking it.', FIX.open_read(path));
      } else if (write && AUTHED.test(cond) && !OWNER.test(cond) && !GATED.test(cond)) {
        add('warning', 'any_signed_in_write', path, EXPLAIN.any_signed_in_write, FIX.any_signed_in_write(path));
      }
    }
  }

  // No match blocks at all, or an explicit test-mode timestamp rule left in.
  const testMode = /allow\s+read,\s*write\s*:\s*if\s+request\.time\s*<\s*timestamp/i.test(text);
  if (testMode) add('critical', 'open_write', '/{document=**}', EXPLAIN.rules_missing, 'Replace the test-mode rule with real per-collection owner rules before launch.');
  if (!blocks.length && !testMode && text.trim()) add('warning', 'rules_missing', '(rules)', 'No match blocks were found in these rules. Confirm this is really your firestore.rules file.', 'Add per-collection rules scoped to request.auth.uid.');

  const seen = new Set();
  const uniq = findings.filter(f => { const k = f.class + '|' + f.table; if (seen.has(k)) return false; seen.add(k); return true; });
  const order = { critical: 0, high: 1, warning: 2 };
  uniq.sort((a, b) => order[a.severity] - order[b.severity]);

  const crit = uniq.filter(f => f.severity === 'critical' || f.severity === 'high').length;
  const warn = uniq.filter(f => f.severity === 'warning').length;
  let guardScore;
  if (crit) guardScore = Math.max(12, 59 - 8 * (crit - 1));
  else if (warn) guardScore = Math.max(70, 79 - 3 * (warn - 1));
  else guardScore = 100;

  return {
    stack: 'firebase',
    guardScore,
    verdict: crit ? 'unsafe' : warn ? 'review' : (total ? 'clear' : 'empty'),
    tableCount: blocks.length,
    counts: { critical: uniq.filter(f => f.severity === 'critical').length, high: uniq.filter(f => f.severity === 'high').length, warning: warn },
    findings: uniq,
  };
}
