// Prisma (schema.prisma) advisor — the 3rd stack, scoped HONESTLY.
//
// Unlike Supabase (Postgres+RLS) and Firebase (rules), Prisma has no declarative
// access-control model of its own: access is enforced in application code, and any
// DB-level protection lives in SQL migrations (which the Postgres/RLS engine reads).
// So this is NOT an attack-proof engine and never claims a table is "safe". It is a
// review-tier advisor that (1) catches an unambiguous critical — a hardcoded
// database connection string — and (2) inventories the models that hold personal
// data so you know what the app layer (and the Postgres RLS engine) must protect.
//
// Verdict caps at 'review' unless a real secret is found; it never returns 'safe',
// because a static read of schema.prisma cannot prove application-layer authz.

export const EXPLAIN = {
  hardcoded_db_url: 'The database connection string is hardcoded here instead of read from an environment variable. Anyone who sees this file can connect directly to your database.',
  no_db_enforcement: 'Prisma enforces access in your application code, not in the database. No SQL migrations with row level security were found, so a single missing check in an API route exposes these models. The deep engine can prove your access rules only from your SQL migrations.',
  pii_model: 'This model holds personal data. Confirm every API path that returns it checks the caller owns the row.',
};

const PII_FIELD = /^(email|phone|password|passwordhash|password_hash|ssn|dob|dateofbirth|address|fullname|full_name|firstname|lastname|token|apikey|api_key|secret|stripecustomerid|stripe_customer_id|creditcard|iban)$/i;

// datasource url that is a literal string, not env("...")
const HARDCODED_URL = /url\s*=\s*"(?:postgres(?:ql)?|mysql|mongodb|sqlserver):\/\/[^"]+"/i;

function parseModels(text) {
  const models = [];
  const re = /model\s+(\w+)\s*\{([\s\S]*?)\}/g;
  let m;
  while ((m = re.exec(text))) {
    const name = m[1];
    const body = m[2];
    const fields = [];
    let hasOwner = false;
    for (const line of body.split('\n')) {
      const fm = /^\s*(\w+)\s+(\w+)/.exec(line);
      if (!fm) continue;
      const field = fm[1], type = fm[2];
      fields.push(field);
      if (/^(userid|user_id|ownerid|owner_id|authorid|author_id|tenantid|tenant_id|organizationid|orgid|org_id)$/i.test(field) || (/^user$/i.test(field) && /User/.test(type))) hasOwner = true;
    }
    models.push({ name, fields, hasOwner, pii: fields.some(f => PII_FIELD.test(f)) });
  }
  return models;
}

export function prismaScan(schemaText, { hasSqlMigrations = false } = {}) {
  const text = String(schemaText || '');
  const findings = [];
  const add = (severity, cls, table, what, fix) => findings.push({ severity, class: cls, table, what, fix });

  if (HARDCODED_URL.test(text)) add('critical', 'hardcoded_db_url', 'datasource', EXPLAIN.hardcoded_db_url,
    'Move the connection string to an env var:\n  datasource db {\n    provider = "postgresql"\n    url      = env("DATABASE_URL")\n  }');

  const models = parseModels(text);
  const piiModels = models.filter(m => m.pii);

  if (!hasSqlMigrations && piiModels.length) add('warning', 'no_db_enforcement', 'schema.prisma', EXPLAIN.no_db_enforcement,
    'Add Postgres row level security in a migration (Prisma runs the SQL), or ensure every query is scoped to the caller. Then run the Postgres engine on your migrations to prove it.');

  for (const m of piiModels) add('warning', 'pii_model', m.name, `${EXPLAIN.pii_model}${m.hasOwner ? ' (an owner/tenant field is present — good; confirm it is enforced)' : ' (no owner/tenant field found — confirm how rows are scoped to a user)'}`,
    m.hasOwner ? 'Enforce the owner/tenant field on every read and write of this model.' : 'Add an owner (userId) or tenant relation and scope every query to it.');

  const critical = findings.filter(f => f.severity === 'critical').length;
  const warn = findings.filter(f => f.severity === 'warning').length;
  let guardScore;
  if (critical) guardScore = Math.max(0, 40 - 10 * (critical - 1));
  else if (warn) guardScore = Math.max(60, 78 - 2 * (warn - 1));
  else guardScore = 90; // never 100: static Prisma read can't prove app-layer authz

  return {
    stack: 'prisma',
    guardScore,
    verdict: critical ? 'unsafe' : 'review', // never 'safe' from a static Prisma read
    modelCount: models.length,
    counts: { critical, high: 0, warning: warn },
    note: 'Prisma access control is enforced in application code; this is a review-tier advisor, not an attack-proof result. Run the Postgres engine on your SQL migrations for proof.',
    findings,
  };
}
