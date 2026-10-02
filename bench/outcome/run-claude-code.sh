#!/usr/bin/env bash
# Outcome benchmark: Claude Code with and without the verifier in its loop.
#
#   bench/outcome/run-claude-code.sh [runs-per-task]        (default 5)
#   MODEL=claude-sonnet-5 bench/outcome/run-claude-code.sh 3
#
# For each task and each run it starts Claude Code headless in a fresh, empty
# folder, twice:
#   baseline     the task prompt only
#   with_verify  the same prompt, plus an instruction to check the migration
#                with vc-check.js and fix what it reports
# Output goes to bench/outcome/runs/<arm>/claude-code/<task>/<run>/.
# Scoring is separate and never trusts the agent: bench/outcome/score.js.
#
# Permissions: the agent may read and write files in its own folder. In the
# with_verify arm it may also run exactly one command: the checker. Nothing else.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
RUNS="${1:-5}"
OUT="$HERE/runs"
CHECKER="$HERE/vc-check.js"
MAX_TURNS="${MAX_TURNS:-30}"
MODEL_ARGS=()
if [ -n "${MODEL:-}" ]; then MODEL_ARGS=(--model "$MODEL"); fi

command -v claude >/dev/null 2>&1 || { echo "Claude Code (claude) is not on your PATH."; exit 1; }
command -v node >/dev/null 2>&1 || { echo "Node.js is not on your PATH."; exit 1; }
[ -d "$HERE/../../node_modules" ] || { echo "Run 'npm install' in the verified-changes folder first."; exit 1; }

SUFFIX_BASE='Write the complete SQL migration to ./migration.sql in the current directory. Do not create any other files. Do not ask questions: make reasonable choices and finish.'

for TASK_DIR in "$HERE"/tasks/*/; do
  TASK="$(basename "$TASK_DIR")"
  PROMPT="$(node -e "process.stdout.write(require('$TASK_DIR/task.json').prompt)")"
  SUFFIX_VERIFY="Before you finish, check your migration by running exactly this command: node $CHECKER --task $TASK migration.sql
It attacks a copy of your database as other users and reports problems with fix instructions. If it prints anything other than SAFE, fix migration.sql and run the check again, up to 5 times."

  for i in $(seq 1 "$RUNS"); do
    for ARM in baseline with_verify; do
      DEST="$OUT/$ARM/claude-code/$TASK/$i"
      if [ -f "$DEST/migration.sql" ]; then echo "skip $ARM $TASK #$i (already done)"; continue; fi
      mkdir -p "$DEST"
      WORK="$(mktemp -d)"
      if [ "$ARM" = baseline ]; then
        FULL="$PROMPT

$SUFFIX_BASE"
        TOOLS=(Read Write Edit)
      else
        FULL="$PROMPT

$SUFFIX_BASE

$SUFFIX_VERIFY"
        TOOLS=(Read Write Edit "Bash(node $CHECKER *)")
      fi
      echo "run  $ARM $TASK #$i"
      START=$(date +%s)
      ( cd "$WORK" && claude -p "$FULL" \
          --output-format json \
          --max-turns "$MAX_TURNS" \
          --permission-mode acceptEdits \
          --allowedTools "${TOOLS[@]}" \
          "${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"}" ) > "$DEST/claude-output.json" 2> "$DEST/claude-stderr.txt"
      echo "{\"seconds\": $(( $(date +%s) - START )), \"arm\": \"$ARM\", \"task\": \"$TASK\", \"run\": $i}" > "$DEST/run.json"
      if [ -f "$WORK/migration.sql" ]; then
        cp "$WORK/migration.sql" "$DEST/migration.sql"
      else
        echo "  no migration.sql produced"
        : > "$DEST/NO_MIGRATION"
      fi
      rm -rf "$WORK"
    done
  done
done

echo
echo "Done. Score with: node $HERE/score.js"
