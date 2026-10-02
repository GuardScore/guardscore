// The Guard Score badge — the viral loop. A vibecoder runs the verifier, drops
// the badge in their README or on their deployed app, and every badge is both
// proof they checked and a nudge for the next person to check theirs. Shape and
// colours match the web front door (web/frontdoor.html) so a score looks the
// same everywhere it appears.
//
// Self-contained SVG (shields.io style), no network, no external font: the two
// text halves are drawn twice, once in a soft shadow and once on top, so it
// reads on any background without depending on a webfont.

const COLOR = score => score == null ? '#8b93a7' : score < 60 ? '#d64550' : score < 80 ? '#b07d05' : '#1f9254';
const WORD = score => score == null ? 'untested' : score < 60 ? 'unsafe' : score < 80 ? 'review' : 'safe';

// Rough width of a Verdana digit/letter run at 11px, so the two halves size to
// their text instead of clipping.
const textWidth = s => Math.ceil([...String(s)].reduce((w, c) => w + (/[a-z]/.test(c) ? 6.2 : /[A-Z0-9]/.test(c) ? 7.2 : c === ' ' ? 3.5 : 6), 0)) + 14;

export function badgeSvg(score, { label = 'Guard Score' } = {}) {
  const val = score == null ? 'n/a' : String(score);
  const c = COLOR(score);
  const lw = textWidth(label);
  const vw = textWidth(val);
  const h = 20, w = lw + vw;
  const t = (x, s, bold) => `<text x="${x}" y="15" fill="#010101" fill-opacity=".3">${s}</text><text x="${x}" y="14"${bold ? ' font-weight="bold"' : ''}>${s}</text>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${label}: ${val}">
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".12"/><stop offset="1" stop-opacity=".12"/></linearGradient>
<clipPath id="r"><rect width="${w}" height="${h}" rx="4"/></clipPath>
<g clip-path="url(#r)">
  <rect width="${lw}" height="${h}" fill="#3a3f4b"/>
  <rect x="${lw}" width="${vw}" height="${h}" fill="${c}"/>
  <rect width="${w}" height="${h}" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,Geneva,sans-serif" font-size="11">
  ${t(lw / 2, label, false)}
  ${t(lw + vw / 2, val, true)}
</g></svg>`;
}

// Markdown a user can paste, pointing the badge at a scoring endpoint and the
// project. Kept here so the CLI, the API and the docs all emit the same snippet.
export function badgeMarkdown(score, { endpoint = 'https://img.shields.io/badge', link = 'https://www.npmjs.com/package/verified-changes' } = {}) {
  const word = WORD(score);
  const color = score == null ? 'lightgrey' : score < 60 ? 'crimson' : score < 80 ? 'goldenrod' : 'forestgreen';
  return `[![Guard Score](${endpoint}/Guard%20Score-${score ?? 'n%2Fa'}%20${word}-${color})](${link})`;
}

export { COLOR as badgeColor, WORD as badgeWord };
