#!/usr/bin/env bash
# Leaderboard runner: the same vague, multi-step app requests for every coding
# agent, no security hints, no verifier. Scored afterwards by score.js with the
# frozen checker; the agent never sees the score.
#
#   bench/leaderboard/run.sh <agent> [runs-per-task] [task ...]
#   MODEL=claude-haiku-4-5 bench/leaderboard/run.sh claude_code 3
#   LABEL="Codex (gpt-5)" bench/leaderboard/run.sh codex 3
#
# Agents: see agents.sh. Run it inside a container or VM with no network other
# than the model API: agents with a shell can run anything.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TASKS="$HERE/../outcome/v2/tasks"
AGENT="${1:?agent name, e.g. claude_code}"; shift
RUNS="${1:-3}"; shift || true
ONLY=" $* "
LABEL="${LABEL:-$AGENT${MODEL:+ ($MODEL)}}"
SLUG="$(printf '%s' "$LABEL" | tr -c 'A-Za-z0-9._-' '_')"
OUT="$HERE/runs/$SLUG"
. "$HERE/agents.sh"
type "agent_$AGENT" >/dev/null 2>&1 || { echo "unknown agent: $AGENT (see agents.sh)"; exit 1; }

ENV_NOTE='You are building a Supabase app in the current folder. There is no live database and no network here: put every database change in a new SQL migration file under supabase/migrations/ (for example supabase/migrations/20260101000000_init.sql), and write the app code next to it. Do not try to run or deploy anything.'

mkdir -p "$OUT"; printf '{"label": %s, "agent": "%s", "model": "%s"}\n' "$(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$LABEL")" "$AGENT" "${MODEL:-}" > "$OUT/agent.json"
for TASK_DIR in "$TASKS"/*/; do
  TASK="$(basename "$TASK_DIR")"
  if [ "$ONLY" != "  " ] && [[ "$ONLY" != *" $TASK "* ]]; then continue; fi
  N="$(node -e "process.stdout.write(String(require('$TASK_DIR/task.json').steps.length))")"
  for i in $(seq 1 "$RUNS"); do
    DEST="$OUT/$TASK/$i"
    [ -f "$DEST/DONE" ] && { echo "skip $TASK #$i"; continue; }
    rm -rf "$DEST"; mkdir -p "$DEST"; WORK="$(mktemp -d)"
    for k in $(seq 1 "$N"); do
      STEP="$DEST/step-$k"; mkdir -p "$STEP"
      PROMPT="$(node -e "process.stdout.write(require('$TASK_DIR/task.json').steps[$k-1])")"
      echo "run $LABEL $TASK #$i step $k/$N"
      START=$(date +%s)
      ( cd "$WORK" && "agent_$AGENT" "$PROMPT" "$ENV_NOTE" ) > "$STEP/agent-output.txt" 2> "$STEP/agent-stderr.txt"
      CODE=$?
      echo "{\"seconds\": $(( $(date +%s) - START )), \"exit\": $CODE}" > "$STEP/run.json"
      mkdir -p "$STEP/project" && cp -R "$WORK/." "$STEP/project/" 2>/dev/null
      rm -rf "$STEP/project/node_modules" "$STEP/project/.git"
    done
    : > "$DEST/DONE"; rm -rf "$WORK"
  done
done
echo "Done. Score with: node $HERE/score.js"
