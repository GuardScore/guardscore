// HTTP API for builder platforms (app builders, hosting platforms, CI systems):
// the platform calls the verifier on every database change its agent makes,
// so safety doesn't depend on the agent choosing to call it.
//
//   GET  /v1/health
//   POST /v1/check   { files, public_tables?, shared_tables? }
//   POST /v1/verify  { files, change_sql, public_tables?, shared_tables? }
//
// files maps paths to contents: supabase/migrations/*.sql (required),
// verified-changes.json, and app source files (checked for leaked keys).
// The response is { verdict, guardScore, findings, fixes (each with proof
// status), ..., report (text for an agent), markdown (for a person) }.
//
// Nothing is stored: each request's files go to a private temp folder that is
// deleted afterwards, the database is an in-process copy that is rolled back,
// and responses carry counts, never row data.
//
// Auth: set VC_API_KEYS to a comma-separated list; callers send
// "Authorization: Bearer <key>". Without VC_API_KEYS the server only listens on
// 127.0.0.1 (local development).
import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { checkFiles, ProjectError } from './project-check.js';
import { formatReport } from './report.js';
import { toMarkdown, toStructured } from './formats.js';
import { badgeSvg } from './badge.js';
import { prewarm } from './db.js';

const webDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'web');
const landingPage = () => { try { return readFileSync(join(webDir, 'frontdoor.html'), 'utf8'); } catch { return '<!doctype html><title>Verified Changes</title><h1>Verified Changes</h1><p>The security verifier for AI-built Supabase apps.</p>'; } };
const sendSvg = (res, svg) => { res.writeHead(200, { 'content-type': 'image/svg+xml', 'cache-control': 'max-age=300' }); res.end(svg); };
const sendHtml = (res, html) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); res.end(html); };

const MAX_BODY = 5 * 1024 * 1024;
const TIMEOUT_MS = 60_000;

const keys = (process.env.VC_API_KEYS || '').split(',').map(s => s.trim()).filter(Boolean).map(k => Buffer.from(k));
const authorized = req => {
  if (!keys.length) return true;
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) return false;
  const got = Buffer.from(m[1]);
  return keys.some(k => k.length === got.length && timingSafeEqual(k, got));
};

const send = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
};

function readBody(req) {
  return new Promise((ok, fail) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { fail(new ProjectError('request body over 5 MB')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { fail(new ProjectError('body is not valid JSON')); } });
    req.on('error', fail);
  });
}

const withTimeout = p => Promise.race([p, new Promise((_, fail) => setTimeout(() => fail(new ProjectError(`check took over ${TIMEOUT_MS / 1000} s`)), TIMEOUT_MS))]);

export function makeServer() {
  return createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && req.url === '/v1/health') return send(res, 200, { ok: true });
      // The zero-install front door: the paste-your-schema scanner page.
      if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) return sendHtml(res, landingPage());
      // The Guard Score badge — the viral loop. GET /v1/badge/<score>.svg, or
      // /badge/<score>.svg; a bare or out-of-range value renders "n/a".
      const badge = req.method === 'GET' && /^\/(v1\/)?badge\/([^/]*?)\.svg$/.exec(req.url || '');
      if (badge) { const n = Number(badge[2]); return sendSvg(res, badgeSvg(Number.isFinite(n) && n >= 0 && n <= 100 ? Math.round(n) : null)); }
      if (req.method !== 'POST' || !['/v1/check', '/v1/verify'].includes(req.url)) return send(res, 404, { error: 'not found' });
      if (!authorized(req)) return send(res, 401, { error: 'missing or wrong API key' });
      const body = await readBody(req);
      const isVerify = req.url === '/v1/verify';
      if (isVerify && typeof body.change_sql !== 'string') return send(res, 400, { error: 'change_sql (string) is required' });
      const run = await withTimeout(checkFiles(body.files, {
        public_tables: body.public_tables || [], shared_tables: body.shared_tables || [],
        ...(isVerify ? { change_sql: body.change_sql } : {}),
      }));
      const r = run.result;
      if (r.verdict === 'invalid_change') return send(res, 200, { verdict: r.verdict, error: r.error });
      send(res, 200, { ...toStructured(r), report: formatReport(r, { kind: run.kind }), markdown: toMarkdown(r, { kind: run.kind }) });
    } catch (e) {
      if (e instanceof ProjectError) send(res, 400, { error: e.message });
      else send(res, 422, { error: `migrations failed to apply: ${e.message}` });
    }
  });
}

export async function startServer({ port = 8787 } = {}) {
  const host = keys.length ? '0.0.0.0' : '127.0.0.1';
  const server = makeServer();
  await new Promise(ok => server.listen(port, host, ok));
  prewarm();
  console.error(`verified-changes API on http://${host}:${port}${keys.length ? '' : ' (no VC_API_KEYS set: local only)'}`);
  return server;
}
