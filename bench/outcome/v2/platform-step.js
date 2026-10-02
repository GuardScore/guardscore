#!/usr/bin/env node
// The platform's side of the with_platform arm: after the agent finishes a
// request, the platform (not the agent) runs the verifier, writes the fixes it
// proved as the next migration, and prints what is left for the agent.
//   node platform-step.js <project-dir>      exit 0 when safe, 1 otherwise
import { resolve } from 'node:path';
import { writeFixMigration } from '../../../src/project-check.js';
import { formatReport } from '../../../src/report.js';

const dir = resolve(process.argv[2] || '.');
try {
  const f = await writeFixMigration(dir, { log: false });
  const head = f.written ? `The platform applied ${f.chosen.length} proven fix(es) as ${f.written}.` : 'The platform had no proven fixes to apply.';
  console.log(`${head}\n\n${formatReport(f.after)}`);
  process.exit(f.after.verdict === 'safe' ? 0 : 1);
} catch (e) {
  const { explainMigrationFailure } = await import('../../../src/project-check.js');
  console.log(`The migrations fail to apply: ${await explainMigrationFailure(dir, e).catch(() => e.message)}. Fix that file (or add a migration after it that makes the rest apply), without adding test data.`);
  process.exit(1);
}
