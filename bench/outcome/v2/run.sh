#!/usr/bin/env bash
# Benchmark v2: vague prompts and multi-step edit sessions, with and without
# the verifier in Claude Code's loop.
#
#   bench/outcome/v2/run.sh [runs-per-task] [task ...]     (default: 1 run, all tasks)
#   MODEL=claude-sonnet-5 bench/outcome/v2/run.sh 3
#   bench/outcome/v2/run.sh 1 journal notes_session          (just these tasks)
#   ARMS="with_mcp" bench/outcome/v2/run.sh 1                  (only the MCP arm)
#   PARALLEL=1 bench/outcome/v2/run.sh 1                       (one at a time; default 4)
#
# Arms: baseline (no verifier), baseline_prompted (security instructions, no
# verifier: the control for prompting), with_verify (the checker as a shell
# command), with_mcp (the verifier as native MCP tools, the way the product ships),
# with_platform (the agent gets no verifier; after every request the platform runs
# it, applies the fixes it proved, and sends what's left back to the agent, up
# to PLATFORM_ROUNDS times, and rejects changes whose migrations don't apply),
# with_mcp_platform (both: the agent has the MCP tools and the platform checks
# after it). Default: baseline and with_verify.
#
# Each run starts Claude Code headless in a fresh, empty folder and sends the
# task's requests one by one in the same conversation (--resume), like a person
# chatting with their builder. After every request the whole project folder is
# snapshotted, so the score can show the step where an app became unsafe.
#
# Both arms get the same short note about the environment (no live database:
# write SQL migrations). The prompts themselves are what a vibecoder would type,
# with no schema and no security rules.
#
# Permissions: read and write files in its own folder. In the with_verify arm
# the agent may also run exactly one command: the checker. Nothing else.
# Scoring is separate and never trusts the agent: bench/outcome/v2/score.js.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
RUNS="${1:-1}"; shift || true
ONLY=" $* "   # plain string: macOS ships bash 3.2, where empty arrays trip set -u
OUT="$HERE/runs"
CHECKER="$HERE/vc-check.js"
MCP_SERVER="$(cd "$HERE/../../.." && pwd)/src/mcp.js"
ARMS="${ARMS:-baseline with_verify}"
# Runs at once. Each is independent (own folder, own conversation). 4 cuts the
# wall-clock time about 4x; lower it if you hit rate limits.
PARALLEL="${PARALLEL:-4}"
# Every arm runs with only the MCP servers given here, so servers installed on
# this machine can't leak into the baseline.
MCP_CONFIG="{\"mcpServers\":{\"verified-changes\":{\"command\":\"node\",\"args\":[\"$MCP_SERVER\"]}}}"
MAX_TURNS="${MAX_TURNS:-40}"
# with_platform: how many times the platform may hand problems back per request.
PLATFORM_ROUNDS="${PLATFORM_ROUNDS:-2}"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
MODEL_ARGS=()
if [ -n "${MODEL:-}" ]; then MODEL_ARGS=(--model "$MODEL"); fi

command -v "$CLAUDE_BIN" >/dev/null 2>&1 || { echo "Claude Code (claude) is not on your PATH."; exit 1; }
command -v node >/dev/null 2>&1 || { echo "Node.js is not on your PATH."; exit 1; }
[ -d "$HERE/../../../node_modules" ] || { echo "Run 'npm install' in the verified-changes folder first."; exit 1; }

ENV_NOTE='You are building a Supabase app in the current folder. There is no live database and no network here: put every database change in a new SQL migration file under supabase/migrations/ (for example supabase/migrations/20260101000000_init.sql). When a later request changes the app, add a new migration file rather than editing old ones. You can skip frontend code. Do not ask questions: make reasonable choices and finish.'
VERIFY_NOTE="This project has a security verifier. When you have finished the database changes for a request, run it once: node $CHECKER .
It builds a copy of the database from supabase/migrations, fills it with sample data for two users, attacks it as an anonymous visitor and as another user, checks real users can still use the app, and prints SAFE or each problem with how to fix it. If a table is meant to be readable by everyone (like a product catalog) or by every signed-in user, list it in verified-changes.json with the reason, as {\"publicTables\": {\"products\": \"the catalog shoppers browse before signing in\"}, \"sharedTables\": {...}}; a table listed without a reason is still checked as private. If the check does not print SAFE, run it again with --fix at the end (node $CHECKER . --fix) to write the fixes it proved as a migration, then fix what is left and run it again, up to 5 times per request."
# Control arm: the same security framing the verifier arms get, with no verifier.
# Separates "the verifier helps" from "reminding the agent about security helps".
PROMPTED_NOTE="Security matters in this project. An anonymous visitor or another signed-in user must not be able to read or change data that isn't theirs, nobody should be able to give themselves admin, and real users must still be able to use their own data. If a table is meant to be readable by everyone (like a product catalog) or by every signed-in user, that's fine."
MCP_NOTE="This project has a security verifier, available as the check_database and verify_change tools. When you have finished the database changes for a request, call check_database once with project_dir set to the current folder (or verify_change for a single migration). It builds a copy of the database from supabase/migrations, fills it with sample data for two users, attacks it as an anonymous visitor and as another user, checks real users can still use the app, and returns SAFE or each problem with how to fix it. If a table is meant to be readable by everyone (like a product catalog) or by every signed-in user, pass it in public_tables or shared_tables as \"table: why it is meant to be open\" (an entry without a reason is ignored). If the result is not SAFE, call apply_fixes to write the fixes it proved as a migration, then fix what is left and check again, up to 5 times per request."

# One run of one task in one arm: every request in order, same conversation.
run_one() {
  local TASK_DIR="$1" TASK="$2" NSTEPS="$3" i="$4" ARM="$5"
  local DEST="$OUT/$ARM/claude-code/$TASK/$i"
  rm -rf "$DEST"; mkdir -p "$DEST"
  local WORK; WORK="$(mktemp -d)"
  local SYS TOOLS MCP_ARGS=(--strict-mcp-config)
  case "$ARM" in
    baseline) SYS="$ENV_NOTE"; TOOLS=(Read Write Edit Glob Grep) ;;
    baseline_prompted) SYS="$ENV_NOTE

$PROMPTED_NOTE"; TOOLS=(Read Write Edit Glob Grep) ;;
    with_verify) SYS="$ENV_NOTE

$VERIFY_NOTE"; TOOLS=(Read Write Edit Glob Grep "Bash(node $CHECKER *)") ;;
    with_mcp) SYS="$ENV_NOTE

$MCP_NOTE"; TOOLS=(Read Write Edit Glob Grep mcp__verified-changes__check_database mcp__verified-changes__verify_change mcp__verified-changes__apply_fixes)
      MCP_ARGS=(--strict-mcp-config --mcp-config "$MCP_CONFIG") ;;
    with_platform) SYS="$ENV_NOTE"; TOOLS=(Read Write Edit Glob Grep) ;;
    with_mcp_platform) SYS="$ENV_NOTE

$MCP_NOTE"; TOOLS=(Read Write Edit Glob Grep mcp__verified-changes__check_database mcp__verified-changes__verify_change mcp__verified-changes__apply_fixes)
      MCP_ARGS=(--strict-mcp-config --mcp-config "$MCP_CONFIG") ;;
    *) echo "unknown arm: $ARM"; return 1 ;;
  esac
  local SID="" k STEP PROMPT START RESUME
  for k in $(seq 1 "$NSTEPS"); do
    STEP="$DEST/step-$k"; mkdir -p "$STEP"
    PROMPT="$(node -e "process.stdout.write(require('$TASK_DIR/task.json').steps[$k-1])")"
    RESUME=(); if [ -n "$SID" ]; then RESUME=(--resume "$SID"); fi
    echo "run  $ARM $TASK #$i step $k/$NSTEPS: $PROMPT"
    START=$(date +%s)
    ( cd "$WORK" && "$CLAUDE_BIN" -p "$PROMPT" \
        "${RESUME[@]+"${RESUME[@]}"}" \
        --append-system-prompt "$SYS" \
        --output-format json \
        --max-turns "$MAX_TURNS" \
        --permission-mode acceptEdits \
        --allowedTools "${TOOLS[@]}" \
        "${MCP_ARGS[@]}" \
        "${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"}" ) > "$STEP/claude-output.json" 2> "$STEP/claude-stderr.txt"
    # The platform's turn: check, apply proven fixes, hand the rest back.
    local ROUNDS=0 PSID
    if [ "$ARM" = with_platform ] || [ "$ARM" = with_mcp_platform ]; then
      PSID="$(node -e "try{process.stdout.write(JSON.parse(require('fs').readFileSync('$STEP/claude-output.json','utf8')).session_id||'')}catch{}")"
      while :; do
        ( cd "$WORK" && node "$HERE/platform-step.js" . ) > "$STEP/platform-$ROUNDS.txt" 2>&1 && break
        [ "$ROUNDS" -ge "$PLATFORM_ROUNDS" ] || [ -z "$PSID" ] && break
        ROUNDS=$((ROUNDS + 1))
        echo "     platform round $ROUNDS: $ARM $TASK #$i step $k"
        ( cd "$WORK" && "$CLAUDE_BIN" -p "The platform ran its security check after your change and has already applied every fix it could prove, as a new migration. These problems are left. Fix them with a new migration, without undoing the platform's fixes:

$(cat "$STEP/platform-$((ROUNDS - 1)).txt")" \
            --resume "$PSID" --append-system-prompt "$SYS" --output-format json --max-turns "$MAX_TURNS" \
            --permission-mode acceptEdits --allowedTools "${TOOLS[@]}" "${MCP_ARGS[@]}" \
            "${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"}" ) > "$STEP/claude-output-round-$ROUNDS.json" 2>> "$STEP/claude-stderr.txt"
        PSID="$(node -e "try{process.stdout.write(JSON.parse(require('fs').readFileSync('$STEP/claude-output-round-$ROUNDS.json','utf8')).session_id||'')}catch{}")"
      done
      # A platform doesn't deploy migrations that fail to apply: roll the
      # migrations back to the last version that applied, and record it.
      local LAST="$STEP/platform-$ROUNDS.txt" REVERTED=0
      if head -1 "$LAST" | grep -q '^The migrations fail to apply'; then
        if [ -d "$DEST/.lastgood" ]; then rm -rf "$WORK/supabase/migrations"; cp -R "$DEST/.lastgood" "$WORK/supabase/migrations"; REVERTED=1; echo "     platform rejected the change (migrations fail): $ARM $TASK #$i step $k"; fi
      else
        rm -rf "$DEST/.lastgood"; [ -d "$WORK/supabase/migrations" ] && cp -R "$WORK/supabase/migrations" "$DEST/.lastgood"
      fi
      echo "$REVERTED" > "$STEP/platform-reverted.txt"
      # Later requests continue the conversation that includes the platform's rounds.
      [ -n "$PSID" ] && node -e "const f=require('fs'),p='$STEP/claude-output.json';try{const o=JSON.parse(f.readFileSync(p,'utf8'));let c=o.total_cost_usd||0;for(let r=1;r<=$ROUNDS;r++){try{c+=JSON.parse(f.readFileSync('$STEP/claude-output-round-'+r+'.json','utf8')).total_cost_usd||0}catch{}}o.session_id='$PSID';o.total_cost_usd=c;o.platform_rounds=$ROUNDS;f.writeFileSync(p,JSON.stringify(o))}catch{}"
    fi
    echo "{\"seconds\": $(( $(date +%s) - START )), \"arm\": \"$ARM\", \"task\": \"$TASK\", \"run\": $i, \"step\": $k, \"platform_rounds\": $ROUNDS}" > "$STEP/run.json"
    mkdir -p "$STEP/project" && cp -R "$WORK/." "$STEP/project/" 2>/dev/null
    rm -rf "$STEP/project/node_modules" "$STEP/project/.claude"
    SID="$(node -e "try{process.stdout.write(JSON.parse(require('fs').readFileSync('$STEP/claude-output.json','utf8')).session_id||'')}catch{}")"
    if [ -z "$SID" ]; then echo "  no session id from step $k; stopping this run (see $STEP/claude-stderr.txt)"; break; fi
  done
  : > "$DEST/DONE"
  rm -rf "$WORK" "$DEST/.lastgood"
  echo "done $ARM $TASK #$i"
}

for TASK_DIR in "$HERE"/tasks/*/; do
  TASK="$(basename "$TASK_DIR")"
  if [ "$ONLY" != "  " ] && [[ "$ONLY" != *" $TASK "* ]]; then continue; fi
  NSTEPS="$(node -e "process.stdout.write(String(require('$TASK_DIR/task.json').steps.length))")"
  for i in $(seq 1 "$RUNS"); do
    for ARM in $ARMS; do
      if [ -f "$OUT/$ARM/claude-code/$TASK/$i/DONE" ]; then echo "skip $ARM $TASK #$i (already done)"; continue; fi
      if [ "$PARALLEL" -le 1 ]; then
        run_one "$TASK_DIR" "$TASK" "$NSTEPS" "$i" "$ARM"
      else
        # Keep at most PARALLEL runs going at once.
        while [ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$PARALLEL" ]; do sleep 2; done
        run_one "$TASK_DIR" "$TASK" "$NSTEPS" "$i" "$ARM" &
      fi
    done
  done
done
wait

echo
echo "Done. Score with: node $HERE/score.js"
