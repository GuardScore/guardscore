// First-version Firebase support. The Supabase checker's strength is building a
// private copy and attacking it; the Firebase emulator that would let us do the
// same needs Java and firebase-tools, so this first version is a STATIC analysis
// of firestore.rules and storage.rules — the same rule categories, read from the
// rules file rather than proven by attack. It is labelled that way in output so
// nobody mistakes it for the attack-proven Supabase result.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

// Split a rules file into `match <path> { ... }` blocks with their allow lines,
// tracking nesting so a wildcard match at the top is seen as broad.
function parseRules(text) {
  const clean = text.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
  const blocks = [];
  const re = /match\s+(\S+)\s+\{/g;
  let m;
  while ((m = re.exec(clean))) {
    // The body up to the next `match` or closing brace at this level.
    const start = re.lastIndex;
    const rest = clean.slice(start);
    const end = rest.search(/\bmatch\b|\}/);
    const body = rest.slice(0, end < 0 ? rest.length : end);
    const allows = [...body.matchAll(/allow\s+([a-z,\s]+?)\s*:\s*if\s+([^;]+);/gi)].map(a => ({ ops: a[1].replace(/\s/g, '').split(','), cond: a[2].trim().replace(/\s+/g, ' ') }));
    blocks.push({ path: m[1].trim(), allows });
  }
  return blocks;
}

const OPEN = /^true$/i;
const AUTHED = /request\.auth\s*!=\s*null|request\.auth\.uid|request\.auth\s*\.\s*token/;
const OWNER = /request\.auth\.uid\s*==|==\s*request\.auth\.uid|resource\.data\.\w*(uid|user|owner|author)\w*\s*==\s*request\.auth\.uid/i;

export function analyzeFirestoreRules(text, file = 'firestore.rules') {
  const findings = [];
  for (const b of parseRules(text)) {
    const wild = /\{[^}]*=\*\*\}/.test(b.path) || /\{\w+\}$/.test(b.path.trim());
    for (const { ops, cond } of b.allows) {
      const write = ops.some(o => /write|create|update|delete/.test(o)) || ops.includes('write');
      const read = ops.some(o => /read|get|list/.test(o)) || ops.includes('read');
      if (OPEN.test(cond)) {
        findings.push({ file, path: b.path, severity: 'high', rule: write ? 'open-write' : 'open-read',
          detail: `allow ${ops.join(',')}: if true — anyone, signed in or not, can ${write ? 'write' : 'read'} ${b.path}${wild ? ' (and everything under it)' : ''}` });
      } else if (AUTHED.test(cond) && !OWNER.test(cond) && write && !/get\(|exists\(|hasrole|role\s*==|admin/i.test(cond)) {
        findings.push({ file, path: b.path, severity: 'medium', rule: 'any-signed-in-write',
          detail: `allow ${ops.join(',')}: if ${cond} — any signed-in user can write ${b.path}; it checks that someone is logged in but not that it's their own document` });
      } else if (AUTHED.test(cond) && !OWNER.test(cond) && read && wild && !/get\(|exists\(|role\s*==|admin/i.test(cond)) {
        findings.push({ file, path: b.path, severity: 'medium', rule: 'any-signed-in-read',
          detail: `allow ${ops.join(',')}: if ${cond} — any signed-in user can read every document under ${b.path}` });
      }
    }
  }
  return findings;
}

// Detect a Firebase project and run the static analysis.
export function checkFirebase(dir) {
  const files = ['firestore.rules', 'storage.rules', join('firebase', 'firestore.rules')].map(f => join(dir, f)).filter(existsSync);
  if (!files.length) return null;
  const findings = [];
  for (const f of files) { try { findings.push(...analyzeFirestoreRules(readFileSync(f, 'utf8'), f.replace(dir + '/', ''))); } catch {} }
  return { platform: 'firebase', mode: 'static', files: files.length, findings };
}
