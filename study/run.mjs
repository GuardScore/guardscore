#!/usr/bin/env node
// Ecosystem study harness — AGGREGATE ONLY. See docs/ecosystem-study.md.
//
// Reads public backend artifacts you have already collected into an input dir
// (Supabase migration .sql files, and firestore.rules files), runs the static
// scanners, and emits aggregate statistics with NO per-source identifiers:
// no filenames, no paths, no repo names in the output. A private index that
// maps a source to its finding — used ONLY to drive responsible disclosure —
// is written separately and must never be published.
//
// Usage:
//   node study/run.mjs <input-dir> [--private-index]
//
// Layout expected under <input-dir> (one folder per sampled source; folder
// names are opaque ids YOU keep private):
//   <input-dir>/<id>/**/*.sql            → scanned as Supabase
//   <input-dir>/<id>/**/firestore.rules  → scanned as Firebase
//
// Output:
//   study/out/aggregate.json   (safe to publish — no identifiers)
//   study/out/private-index.json (ONLY with --private-index; DO NOT publish)

import { readdirSync, readFileSync, statSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, extname, basename } from 'node:path';
import { staticScan } from '../web/scan.js';
import { firestoreScan } from '../web/firebase-scan.js';

const inputDir = process.argv[2];
const keepPrivate = process.argv.includes('--private-index');
if (!inputDir) { console.error('usage: node study/run.mjs <input-dir> [--private-index]'); process.exit(2); }

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

// Each immediate subdir of inputDir is one sampled source, keyed by an opaque id.
const sources = readdirSync(inputDir).filter(n => statSync(join(inputDir, n)).isDirectory());

const bucket = n => n == null ? 'n/a' : n < 40 ? '0-39' : n < 60 ? '40-59' : n < 80 ? '60-79' : n < 100 ? '80-99' : '100';
const agg = {
  generatedAt: new Date().toISOString().slice(0, 10),
  n: 0,
  byStack: { supabase: 0, firebase: 0 },
  withCritical: 0,
  withAnyFinding: 0,
  scoreHistogram: { '0-39': 0, '40-59': 0, '60-79': 0, '80-99': 0, '100': 0, 'n/a': 0 },
  patternFrequency: {},   // class -> count of SOURCES with >=1 of that class
  dataClassExposure: { personal_data_anon_read: 0, anon_write: 0, public_private_bucket: 0 },
};
const privateIndex = []; // id -> {stack, guardScore, classes} — DISCLOSURE ONLY, never published

for (const id of sources) {
  const root = join(inputDir, id);
  const files = walk(root);
  const sqls = files.filter(f => extname(f) === '.sql');
  const rules = files.filter(f => basename(f) === 'firestore.rules');
  if (!sqls.length && !rules.length) continue;

  let r, stack;
  if (sqls.length) { stack = 'supabase'; r = staticScan(sqls.map(f => readFileSync(f, 'utf8')).join('\n;\n')); }
  else { stack = 'firebase'; r = firestoreScan(rules.map(f => readFileSync(f, 'utf8')).join('\n')); }

  agg.n++;
  agg.byStack[stack]++;
  const classes = [...new Set(r.findings.map(f => f.class))];
  const hasCrit = r.findings.some(f => f.severity === 'critical' || f.severity === 'high');
  if (hasCrit) agg.withCritical++;
  if (r.findings.length) agg.withAnyFinding++;
  agg.scoreHistogram[bucket(r.guardScore)]++;
  for (const c of classes) agg.patternFrequency[c] = (agg.patternFrequency[c] || 0) + 1;
  if (r.findings.some(f => f.class === 'anon_read' && f.severity === 'critical')) agg.dataClassExposure.personal_data_anon_read++;
  if (r.findings.some(f => f.class === 'anon_write' || f.class === 'open_write')) agg.dataClassExposure.anon_write++;
  if (r.findings.some(f => f.class === 'public_bucket')) agg.dataClassExposure.public_private_bucket++;

  if (keepPrivate) privateIndex.push({ id, stack, guardScore: r.guardScore, verdict: r.verdict, classes });
}

// Percentages for the headline (rounded; raw counts kept for honesty).
agg.pct = {
  withCritical: agg.n ? Math.round(100 * agg.withCritical / agg.n) : 0,
  withAnyFinding: agg.n ? Math.round(100 * agg.withAnyFinding / agg.n) : 0,
};

mkdirSync(join('study', 'out'), { recursive: true });
writeFileSync(join('study', 'out', 'aggregate.json'), JSON.stringify(agg, null, 2));
console.log(`study: scanned ${agg.n} sources → study/out/aggregate.json`);
console.log(`  ${agg.pct.withCritical}% have a critical leak · ${agg.pct.withAnyFinding}% have any finding`);
if (keepPrivate) {
  writeFileSync(join('study', 'out', 'private-index.json'), JSON.stringify(privateIndex, null, 2));
  console.warn('  WROTE study/out/private-index.json — DISCLOSURE ONLY. Never publish. Gitignore it.');
}
