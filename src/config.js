// Project settings that decide security outside the database policies:
// Supabase auth settings in supabase/config.toml, and secrets committed to git
// history. These are read, not attacked, so they come back as warnings with the
// exact setting and line, never as a changed verdict.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

// Just enough TOML for config.toml: [sections] and key = value lines.
export function readToml(text) {
  const out = {};
  let section = '';
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, '').trim();
    const sec = line.match(/^\[([^\]]+)\]$/);
    if (sec) { section = sec[1].trim(); return; }
    const kv = line.match(/^([A-Za-z0-9_]+)\s*=\s*(.+)$/);
    if (kv) out[`${section}.${kv[1]}`] = { value: kv[2].replace(/^"|"$/g, ''), line: i + 1 };
  });
  return out;
}

const RULES = [
  { key: 'auth.email.enable_confirmations', bad: v => v === 'false', level: 'warn',
    detail: 'email confirmation is off: anyone can sign up with someone else\'s email address and use the account right away' },
  { key: 'auth.minimum_password_length', bad: v => Number(v) < 8, level: 'warn',
    detail: v => `the minimum password length is ${v}; 8 or more stops the easiest guessing` },
  { key: 'auth.jwt_expiry', bad: v => Number(v) > 7 * 24 * 3600, level: 'warn',
    detail: v => `sign-in tokens stay valid for ${Math.round(Number(v) / 86400)} days; a stolen token works that long` },
  { key: 'auth.enable_anonymous_sign_ins', bad: v => v === 'true', level: 'info',
    detail: 'anonymous sign-ins are on: anonymous users get the "authenticated" role, so every policy written for signed-in users also lets them in unless it checks is_anonymous' },
  { key: 'auth.email.double_confirm_changes', bad: v => v === 'false', level: 'warn',
    detail: 'changing an account\'s email doesn\'t need confirmation from the old address, which makes account takeover easier' },
];

export function configChecks(dir) {
  const out = [];
  const f = join(dir, 'supabase', 'config.toml');
  if (existsSync(f)) {
    const cfg = readToml(readFileSync(f, 'utf8'));
    for (const r of RULES) {
      const v = cfg[r.key];
      if (v && r.bad(v.value)) out.push({ level: r.level, file: 'supabase/config.toml', line: v.line, setting: r.key, detail: (typeof r.detail === 'function' ? r.detail(v.value) : r.detail) + ' (this file sets local development; check the same setting in the hosted project\'s Auth settings)' });
    }
    for (const [k, v] of Object.entries(cfg)) {
      const m = k.match(/^storage\.buckets\.([^.]+)\.public$/);
      if (m && v.value === 'true') out.push({ level: /doc|invoice|receipt|private|secure|contract|passport|medical|report|backup|export|id_?card/i.test(m[1]) ? 'warn' : 'info', file: 'supabase/config.toml', line: v.line, setting: k, detail: `bucket "${m[1]}" is public: anyone with a file's URL can download it, whatever the storage policies say` });
    }
  }
  out.push(...gitHistorySecrets(dir));
  return out;
}

// A service-role key committed once stays in git history even after it is
// deleted from the files, so it must be rotated.
function gitHistorySecrets(dir) {
  if (!existsSync(join(dir, '.git'))) return [];
  const log = spawnSync('git', ['-C', dir, 'log', '--all', '-p', '--no-color', '--format=commit %H', '-G', 'eyJ|sb_secret_'], { encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 });
  if (log.status !== 0 || !log.stdout) return [];
  const found = new Map();
  let commit = '';
  for (const line of log.stdout.split('\n')) {
    if (line.startsWith('commit ')) { commit = line.slice(7, 19); continue; }
    if (!line.startsWith('+') && !line.startsWith('-')) continue;
    for (const m of line.matchAll(/eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}|sb_secret_[A-Za-z0-9_-]{10,}/g)) {
      let role = m[0].startsWith('sb_secret_') ? 'service_role' : null;
      if (!role) try { const pl = JSON.parse(Buffer.from(m[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); role = pl.iss === 'supabase-demo' ? null : pl.role; } catch {}
      if (role === 'service_role' && !found.has(m[0])) found.set(m[0], commit);
    }
  }
  return [...found].map(([k, c]) => ({ level: 'warn', file: `git history (commit ${c})`, setting: 'service-role key', detail: `a service-role key (${k.slice(0, 12)}…) is in this repository's git history; deleting the file doesn't remove it, so rotate the key in the Supabase dashboard` }));
}
