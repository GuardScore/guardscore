#!/usr/bin/env node
// ──────────────────────────────────────────────────────────────────────────
//  Ecosystem study — COLLECTOR.  Public source code only.
//
//  LEGAL / ETHICAL SCOPE (read before running):
//    • This reads PUBLIC source files from PUBLIC GitHub repos through the
//      GitHub API with a read-only token. That is analysis of published code.
//    • It NEVER connects to anyone's live app, database, or endpoint, never
//      uses anyone's API keys, and never attempts access to any running system.
//      No live attacking. That distinction is what keeps the study lawful and
//      on the right side of the product's own Terms of Use.
//    • Output is aggregate-only (see run.mjs). A private id→repo manifest is
//      written under study/input/ (gitignored) solely to allow responsible
//      disclosure to affected projects. Never publish it.
//
//  USAGE:
//    GITHUB_TOKEN=ghp_xxx node study/collect.mjs [--max 60] [--stack both]
//  then:
//    node study/run.mjs study/input --private-index
//
//  A fine-grained or classic PAT with public-repo read scope is enough.
// ──────────────────────────────────────────────────────────────────────────
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
if (!TOKEN) { console.error('Set GITHUB_TOKEN (read-only PAT). See the header for scope.'); process.exit(2); }

const arg = (k, d) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; };
const MAX = Math.max(1, parseInt(arg('--max', '60'), 10) || 60);   // max repos per stack
const STACK = arg('--stack', 'both');                               // supabase | firebase | both
const INPUT = join('study', 'input');

const API = 'https://api.github.com';
const H = { 'Authorization': `Bearer ${TOKEN}`, 'Accept': 'application/vnd.github+json', 'User-Agent': 'guardscore-study' };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const id = s => createHash('sha256').update(s).digest('hex').slice(0, 16); // opaque, stable per repo

async function gh(path, { raw = false } = {}) {
  for (let attempt = 0; attempt < 6; attempt++) {
    const res = await fetch(path.startsWith('http') ? path : API + path, { headers: H });
    if (res.status === 403 || res.status === 429) {
      const reset = Number(res.headers.get('x-ratelimit-reset')) * 1000;
      const wait = Math.min(60000, Math.max(2000, reset - Date.now()));
      console.error(`  rate-limited, waiting ${Math.round(wait / 1000)}s…`);
      await sleep(wait); continue;
    }
    if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${path}`);
    return raw ? res.text() : res.json();
  }
  throw new Error('giving up after repeated rate limits');
}

// Code search → unique public, non-fork repos. `q` must include a term + qualifiers.
async function findRepos(q, want) {
  const repos = new Map(); // full_name -> {full_name, default_branch}
  for (let page = 1; page <= 10 && repos.size < want; page++) {
    let data;
    try { data = await gh(`/search/code?q=${encodeURIComponent(q)}&per_page=100&page=${page}`); }
    catch (e) { console.error('  search error:', e.message); break; }
    if (!data.items || !data.items.length) break;
    for (const it of data.items) {
      const r = it.repository;
      if (!r || r.private || r.fork) continue;
      if (!repos.has(r.full_name)) repos.set(r.full_name, { full_name: r.full_name, default_branch: r.default_branch || 'HEAD' });
      if (repos.size >= want) break;
    }
    await sleep(2500); // code search secondary-rate-limit friendly
  }
  return [...repos.values()];
}

async function listDir(full, path, ref) {
  try { const d = await gh(`/repos/${full}/contents/${encodeURIComponent(path)}?ref=${ref}`);
    return Array.isArray(d) ? d : []; } catch { return []; }
}
async function getFile(full, path, ref) {
  try { const d = await gh(`/repos/${full}/contents/${encodeURIComponent(path)}?ref=${ref}`);
    if (d && d.content && d.encoding === 'base64') return Buffer.from(d.content, 'base64').toString('utf8');
  } catch {} return null;
}

function save(opaque, relPath, content) {
  const dir = join(INPUT, opaque, relPath.split('/').slice(0, -1).join('/'));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(INPUT, opaque, relPath), content);
}

async function collectSupabase(want, manifest) {
  console.log(`\nSupabase: searching public repos with supabase/migrations …`);
  const repos = await findRepos('policy path:supabase/migrations extension:sql', want);
  console.log(`  ${repos.length} candidate repos`);
  let n = 0;
  for (const r of repos) {
    const files = await listDir(r.full_name, 'supabase/migrations', r.default_branch);
    const sqls = files.filter(f => f.type === 'file' && f.name.endsWith('.sql')).slice(0, 40);
    if (!sqls.length) { await sleep(400); continue; }
    const oid = id(r.full_name);
    let got = 0;
    for (const f of sqls) {
      const c = await getFile(r.full_name, f.path, r.default_branch);
      if (c) { save(oid, f.path, c); got++; }
      await sleep(250);
    }
    if (got) { manifest.push({ id: oid, repo: r.full_name, stack: 'supabase', files: got }); n++; console.log(`  [${n}] ${r.full_name} (${got} migrations)`); }
    await sleep(500);
  }
  return n;
}

async function collectFirebase(want, manifest) {
  console.log(`\nFirebase: searching public repos with firestore.rules …`);
  const repos = await findRepos('rules_version filename:firestore.rules', want);
  console.log(`  ${repos.length} candidate repos`);
  let n = 0;
  for (const r of repos) {
    const c = await getFile(r.full_name, 'firestore.rules', r.default_branch);
    if (c) { const oid = id(r.full_name); save(oid, 'firestore.rules', c); manifest.push({ id: oid, repo: r.full_name, stack: 'firebase', files: 1 }); n++; console.log(`  [${n}] ${r.full_name}`); }
    await sleep(500);
  }
  return n;
}

(async () => {
  mkdirSync(INPUT, { recursive: true });
  const manifest = existsSync(join(INPUT, '_manifest.json'))
    ? JSON.parse(readFileSync(join(INPUT, '_manifest.json'), 'utf8')) : [];
  const have = new Set(manifest.map(m => m.repo));
  const before = manifest.length;

  let s = 0, f = 0;
  if (STACK === 'both' || STACK === 'supabase') s = await collectSupabase(MAX, manifest);
  if (STACK === 'both' || STACK === 'firebase') f = await collectFirebase(MAX, manifest);

  // de-dup manifest by repo (in case of re-runs)
  const seen = new Set(); const dedup = [];
  for (const m of manifest) { if (seen.has(m.repo)) continue; seen.add(m.repo); dedup.push(m); }
  writeFileSync(join(INPUT, '_manifest.json'), JSON.stringify(dedup, null, 2));

  console.log(`\nCollected ${dedup.length - before} new sources (supabase +${s}, firebase +${f}). Total: ${dedup.length}.`);
  console.log('Private manifest: study/input/_manifest.json (gitignored — disclosure only).');
  console.log('\nNext:  node study/run.mjs study/input --private-index');
})();
