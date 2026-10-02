// Vercel serverless function: the Guard Score badge endpoint.
//   /api/badge?score=59   or, via the rewrite in vercel.json,   /badge/59.svg
// Mirrors src/badge.js. Kept inline so this function has no bundle step.

const COLOR = s => s == null ? '#8b93a7' : s < 60 ? '#d64550' : s < 80 ? '#b07d05' : '#1f9254';
const textWidth = s => Math.ceil([...String(s)].reduce((w, c) => w + (/[a-z]/.test(c) ? 6.2 : /[A-Z0-9]/.test(c) ? 7.2 : c === ' ' ? 3.5 : 6), 0)) + 14;

function badgeSvg(score, label = 'Guard Score') {
  const val = score == null ? 'n/a' : String(score);
  const c = COLOR(score);
  const lw = textWidth(label), vw = textWidth(val), h = 20, w = lw + vw;
  const t = (x, s, bold) => `<text x="${x}" y="15" fill="#010101" fill-opacity=".3">${s}</text><text x="${x}" y="14"${bold ? ' font-weight="bold"' : ''}>${s}</text>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${label}: ${val}">
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".12"/><stop offset="1" stop-opacity=".12"/></linearGradient>
<clipPath id="r"><rect width="${w}" height="${h}" rx="4"/></clipPath>
<g clip-path="url(#r)"><rect width="${lw}" height="${h}" fill="#3a3f4b"/><rect x="${lw}" width="${vw}" height="${h}" fill="${c}"/><rect width="${w}" height="${h}" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,Geneva,sans-serif" font-size="11">${t(lw / 2, label, false)}${t(lw + vw / 2, val, true)}</g></svg>`;
}

module.exports = function handler(req, res) {
  const raw = (req.query && req.query.score) != null ? req.query.score
    : ((req.url || '').match(/badge\/([^/.]+)/) || [])[1];
  const n = Number(raw);
  const score = Number.isFinite(n) && n >= 0 && n <= 100 ? Math.round(n) : null;
  res.setHeader('content-type', 'image/svg+xml; charset=utf-8');
  res.setHeader('cache-control', 'public, max-age=300, s-maxage=300');
  res.setHeader('access-control-allow-origin', '*');
  res.statusCode = 200;
  res.end(badgeSvg(score));
};
