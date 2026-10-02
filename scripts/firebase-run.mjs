#!/usr/bin/env node
// One-command Firebase attack run. Intended to be launched by firebase-tools:
//
//   firebase emulators:exec --only firestore,auth,storage "node scripts/firebase-run.mjs <project-dir>"
//
// or via the npm script:  npm run firebase:check -- <project-dir>
//
// firebase-tools starts the emulators, sets FIRESTORE_EMULATOR_HOST /
// FIREBASE_AUTH_EMULATOR_HOST in the environment, runs this, then tears them down.
import { emulatorChannel } from '../src/firebase/emulator.js';
import { verifyFirebase } from '../src/firebase/verify.js';
import { renderResult } from '../src/render.js';

const dir = process.argv[2] || '.';
const channel = await emulatorChannel({ projectDir: dir });
const r = await verifyFirebase({ projectDir: dir, channel });
console.log(renderResult(r, { format: process.argv.includes('--json') ? 'json' : 'text' }));
process.exit(r.verdict === 'safe' ? 0 : r.verdict === 'untested' ? 2 : 1);
