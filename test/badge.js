// The Guard Score badge and the web front door served by the API — the viral
// surface. Checks the badge renders the right colour band for a score, the
// endpoints answer, and the landing page is really the scanner.
import { badgeSvg, badgeMarkdown, badgeColor, badgeWord } from '../src/badge.js';
import { makeServer } from '../src/server.js';

let fail = 0;
const ok = (cond, msg) => { if (!cond) { fail++; console.log('  FAIL', msg); } };

// Colour bands match the Guard Score meaning: <60 unsafe (red), <80 review (amber), else safe (green).
ok(badgeColor(35) === '#d64550' && badgeWord(35) === 'unsafe', 'low score → red / unsafe');
ok(badgeColor(72) === '#b07d05' && badgeWord(72) === 'review', 'mid score → amber / review');
ok(badgeColor(100) === '#1f9254' && badgeWord(100) === 'safe', 'high score → green / safe');
ok(badgeColor(null) === '#8b93a7' && badgeWord(null) === 'untested', 'no score → grey / untested');

// The SVG is well-formed, self-contained, carries the score, and has a viewBox
// so it scales instead of clipping when a README constrains its width.
const svg = badgeSvg(59);
ok(svg.startsWith('<svg') && svg.trim().endsWith('</svg>'), 'badge is a single <svg>');
ok(/aria-label="Guard Score: 59"/.test(svg), 'badge announces the score');
ok(/viewBox="0 0 \d+ \d+"/.test(svg), 'badge has a viewBox (scales, not clips)');
ok(!/https?:\/\/(?!www\.w3\.org)/.test(svg), 'badge pulls nothing off the network (only the SVG namespace URI)');
ok(/#d64550/.test(svg), 'badge 59 is red');
ok(badgeSvg(null).includes('n/a'), 'no-score badge reads n/a');

// The markdown snippet is paste-ready and links back to the tool.
const md = badgeMarkdown(59);
ok(md.startsWith('[![Guard Score]') && md.includes('verified-changes'), 'markdown snippet links to the project');

// The API serves the badge and the front door without an API key (they are public).
const srv = makeServer();
await new Promise(r => srv.listen(0, '127.0.0.1', r));
const port = srv.address().port;
const get = p => fetch(`http://127.0.0.1:${port}${p}`).then(async r => ({ status: r.status, ct: r.headers.get('content-type') || '', body: await r.text() }));

const badge = await get('/v1/badge/59.svg');
ok(badge.status === 200 && /image\/svg/.test(badge.ct) && /Guard Score: 59/.test(badge.body), 'GET /v1/badge/59.svg serves the SVG');
const badge2 = await get('/badge/95.svg');
ok(badge2.status === 200 && /#1f9254/.test(badge2.body), 'GET /badge/95.svg serves a green badge');
const oob = await get('/v1/badge/999.svg');
ok(oob.status === 200 && /n\/a/.test(oob.body), 'out-of-range score → n/a badge, not an error');
const landing = await get('/');
ok(landing.status === 200 && /text\/html/.test(landing.ct) && /leaking user data/.test(landing.body) && /staticScan/.test(landing.body) && /firestoreScan/.test(landing.body), 'GET / serves the multi-stack scanner front door');
srv.close();

console.log(fail ? `badge: ${fail} check(s) failed` : 'badge checks passed (Guard Score badge + web front door)');
process.exit(fail ? 1 : 0);
