// Prisma advisor — honest scoping: catches a hardcoded DB URL, inventories PII
// models, and NEVER returns 'safe' from a static read.
import { prismaScan } from '../web/prisma-scan.js';

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.log('  FAIL', m); } };

const SCHEMA = `
datasource db { provider = "postgresql"  url = env("DATABASE_URL") }
model User {
  id    String @id
  email String
  posts Post[]
}
model Post {
  id     String @id
  title  String
  userId String
  user   User   @relation(fields: [userId], references: [id])
}
`;

const r = prismaScan(SCHEMA, { hasSqlMigrations: false });
ok(r.stack === 'prisma' && r.verdict === 'review', 'clean-ish Prisma schema → review, never safe');
ok(r.guardScore < 100, 'never scores 100 from a static Prisma read');
ok(r.findings.some(f => f.class === 'pii_model' && f.table === 'User'), 'inventories the PII model (User has email)');
ok(r.findings.some(f => f.class === 'no_db_enforcement'), 'warns that no DB-level enforcement was found');

// hardcoded connection string → critical / unsafe
const bad = prismaScan(`datasource db { provider="postgresql" url = "postgresql://admin:pw@db.example.com:5432/app" }\nmodel A { id String @id }`, { hasSqlMigrations: true });
ok(bad.verdict === 'unsafe' && bad.findings.some(f => f.class === 'hardcoded_db_url'), 'flags a hardcoded database URL as critical');

// with SQL migrations present, the no-enforcement warning is suppressed
const withMig = prismaScan(SCHEMA, { hasSqlMigrations: true });
ok(!withMig.findings.some(f => f.class === 'no_db_enforcement'), 'no-enforcement warning suppressed when SQL migrations exist');

console.log(fail ? `prisma-scan: ${fail} failed` : 'prisma-scan checks passed (Prisma advisor, honestly scoped)');
process.exit(fail ? 1 : 0);
