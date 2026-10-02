// Sample rows that satisfy an app's own CHECK rules, so the verifier can test
// tables whose columns have a format (a 64-character hex hash, an 8-letter
// code, a minimum length) or rules between columns ("a <> b", "if visibility
// is X then these are empty"). Only columns a rule mentions are changed.

// A string matching a simple anchored pattern like ^[a-z0-9]{6,12}$ or
// ^[A-Z0-9]+$. Characters alternate between the ranges of each class, so a
// value also satisfies companion rules such as "contains a digit".
export function sampleForPattern(re, seed = 0) {
  const m = String(re).match(/^\^(.*)\$$/);
  if (!m) return null;
  // Plain groups with no alternation or quantifier add nothing: flatten them.
  // Optional groups ((?:-[a-z0-9]+)* or (...)?) can be left out; plain and
  // one-or-more groups are used once.
  // Alternation inside a group ((0[1-9]|1[0-2])): the first alternative will do.
  // POSIX classes as in Postgres ([[:space:]], [[:alpha:]]).
  let src = m[1].replace(/\[:space:\]/g, ' \\t').replace(/\[:alpha:\]/g, 'a-zA-Z').replace(/\[:digit:\]/g, '0-9').replace(/\[:alnum:\]/g, 'a-zA-Z0-9').replace(/\[:lower:\]/g, 'a-z').replace(/\[:upper:\]/g, 'A-Z');
  for (let prev; prev !== src;) { prev = src; src = src.replace(/\((\?:)?([^()|]*)\|[^()]*\)/, '($1$2)'); }
  const body = src.replace(/\((?:\?:)?[^()|]*\)[*?]/g, '').replace(/\((?:\?:)?([^()|]*)\)(\+|\{1(?:,\d*)?\})?/g, '$1');
  let out = '';
  const atom = /(\[(\^?)((?:\\.|[^\]])+)\]|\\d|\\w|\.|\\.|[^[\\{+*?])(\{(\d+)(?:,(\d*))?\}|\+|\*|\?)?/gy;
  let a;
  while (atom.lastIndex < body.length && (a = atom.exec(body))) {
    const [, tok, neg, cls, quant, qmin] = a;
    let pools;
    if (cls && neg) {
      const inCls = new RegExp(`[${cls}]`);
      const pool = [...'abcxyz123'].filter(ch => !inCls.test(ch));
      if (!pool.length) return null;
      pools = [pool];
    } else if (cls) {
      pools = [];
      const parts = cls.replace(/\\-/g, '\u0000').match(/.-.|\\.|./g) || [];
      for (const p of parts) {
        if (/^.-.$/.test(p)) { const lo = p.charCodeAt(0), hi = p.charCodeAt(2); pools.push(Array.from({ length: hi - lo + 1 }, (_, i) => String.fromCharCode(lo + i))); }
        else pools.push([p === '\u0000' ? '-' : p.replace(/^\\/, '')]);
      }
    } else if (tok === '\\d') pools = [['1', '2', '3']];
    else if (tok === '\\w' || tok === '.') pools = [['a'], ['1']];
    else pools = [[tok.replace(/^\\/, '')]];
    let n = 1;
    if (quant === '+') n = 8;
    else if (quant === '*' || quant === '?') n = quant === '?' ? 1 : 4;
    else if (qmin !== undefined) n = Number(qmin) || 1;
    // seed shifts the characters so two sample rows get different values
    // (unique handles), still inside each class.
    for (let i = 0; i < n; i++) { const pool = pools[i % pools.length]; out += pool[(Math.floor(i / pools.length) + seed * (i + 1)) % pool.length]; }
  }
  if (atom.lastIndex < body.length) return null;
  // Only a value the rule itself accepts.
  try { return new RegExp(`^${src}$`).test(out) ? out : null; } catch { return null; }
}

const lit = v => `'${String(v).replace(/'/g, "''")}'`;
const unlit = v => (/^'.*'$/s.test(v) ? v.slice(1, -1).replace(/''/g, "'") : v);

// Adjust a row (column -> SQL literal) to satisfy one CHECK definition.
// other: a value to use when a rule says two columns must differ.
export function fitCheck(def, values, columns, other, seed = 0) {
  const cols = new Set(columns);
  // An OR of alternatives: satisfy the first one.
  let expr = def.replace(/^CHECK\s*/i, '').replace(/\s+NOT VALID\s*$/i, '');
  const branches = splitTopLevel(stripParens(expr), /\s+OR\s+/i);
  if (branches.length > 1) expr = branches[0];
  // Numeric ranges (latitude between -29.5 and -25.8): collect the bounds.
  const num = x => Number(String(x).replace(/[()'\s]|::[\w ]+/g, ''));
  const bounds = {};
  for (const cond of splitTopLevel(stripParens(expr), /\s+AND\s+/i)) {
    const c = stripParens(cond);
    const mm = c.match(/^"?(\w+)"?\s*(>=|>|<=|<)\s*(.+)$/);
    if (mm && cols.has(mm[1]) && Number.isFinite(num(mm[3]))) {
      const b = bounds[mm[1]] ||= {};
      if (mm[2][0] === '>') b.lo = num(mm[3]) + (mm[2] === '>' ? 1e-6 : 0); else b.hi = num(mm[3]) - (mm[2] === '<' ? 1e-6 : 0);
    }
    const bt = c.match(/^"?(\w+)"?\s+BETWEEN\s+(.+?)\s+AND\s+(.+)$/i);
    if (bt && cols.has(bt[1])) bounds[bt[1]] = { lo: num(bt[2]), hi: num(bt[3]) };
  }
  for (const [col, b] of Object.entries(bounds)) {
    const cur = Number(unlit(values[col] ?? 'NaN'));
    const ok = Number.isFinite(cur) && (b.lo === undefined || cur >= b.lo) && (b.hi === undefined || cur <= b.hi);
    if (!ok) values[col] = String(b.lo !== undefined && b.hi !== undefined ? (b.lo + b.hi) / 2 : b.lo !== undefined ? Math.ceil(b.lo) : Math.floor(b.hi));
  }
  for (const cond of splitTopLevel(stripParens(expr), /\s+AND\s+/i)) {
    const c = stripParens(cond);
    let m;
    if ((m = c.match(/^"?(\w+)"?\s*(?:=|~~)\s*'((?:[^']|'')*)'(?:::\w+(?:\s+\w+)*)?$/)) && cols.has(m[1])) values[m[1]] = lit(m[2].replace(/''/g, "'"));
    else if ((m = c.match(/^"?(\w+)"?\s+IS\s+NULL$/i)) && cols.has(m[1])) values[m[1]] = 'null';
    else if ((m = c.match(/^jsonb?_typeof\(\s*"?(\w+)"?\s*\)\s*=\s*'(object|array)'/i)) && cols.has(m[1])) values[m[1]] = m[2].toLowerCase() === 'array' ? `'[]'` : `'{}'`;
    else if ((m = c.match(/^"?(\w+)"?\s*<>\s*''(?:::\w+)?$/)) && cols.has(m[1]) && ['', "''"].includes(values[m[1]] ?? "''")) values[m[1]] = lit(/email/i.test(m[1]) ? `vc${seed}@example.test` : `value-${seed}`);
    else if ((m = c.match(/^"?(\w+)"?\s*~\*?\s*'((?:[^']|'')*)'/)) && cols.has(m[1])) {
      const s = sampleForPattern(m[2].replace(/''/g, "'"), seed);
      if (s != null) values[m[1]] = lit(s);
    } else if ((m = c.match(/^(?:char_)?length\(\s*"?(\w+)"?\s*\)\s*(>=|>|=)\s*(\d+)$/i)) && cols.has(m[1])) {
      const n = Number(m[3]) + (m[2] === '>' ? 1 : 0);
      const cur = unlit(values[m[1]] ?? '');
      if (cur.length < n || m[2] === '=') values[m[1]] = lit((cur + 'x'.repeat(n)).slice(0, Math.max(n, m[2] === '=' ? n : cur.length)));
    } else if ((m = c.match(/^(?:char_)?length\(\s*"?(\w+)"?\s*\)\s*(<=|<)\s*(\d+)$/i)) && cols.has(m[1])) {
      const n = Number(m[3]) - (m[2] === '<' ? 1 : 0);
      const cur = unlit(values[m[1]] ?? '');
      if (cur.length > n) values[m[1]] = lit(cur.slice(0, n));
    } else if ((m = c.match(/^(?:cardinality|array_length)\(\s*"?(\w+)"?(?:\s*,\s*1)?\s*\)\s*>=?\s*(\d+)$/i)) && cols.has(m[1])) {
      values[m[1]] = `array[${Array.from({ length: Math.max(1, Number(m[2])) }, (_, i) => lit(`item${i + 1}`)).join(', ')}]`;
    } else if ((m = c.match(/^"?(\w+)"?\s*<>\s*"?(\w+)"?$/)) && cols.has(m[1]) && cols.has(m[2]) && values[m[1]] === values[m[2]] && other) {
      values[m[2]] = other;
    }
  }
  return values;
}

export function stripParens(s) {
  s = s.trim();
  while (s.startsWith('(') && s.endsWith(')') && balanced(s.slice(1, -1))) s = s.slice(1, -1).trim();
  return s;
}
function balanced(s) {
  let d = 0, q = false;
  for (const ch of s) { if (ch === "'") q = !q; else if (!q) { if (ch === '(') d++; else if (ch === ')' && --d < 0) return false; } }
  return d === 0;
}
export function splitTopLevel(s, sep) {
  const out = []; let d = 0, q = false, start = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "'") q = !q;
    else if (!q && ch === '(') d++;
    else if (!q && ch === ')') d--;
    else if (!q && d === 0) {
      const m = s.slice(i).match(new RegExp('^' + sep.source, 'i'));
      if (m) { out.push(s.slice(start, i)); i += m[0].length - 1; start = i + 1; }
    }
  }
  out.push(s.slice(start));
  return out.map(x => x.trim()).filter(Boolean);
}
