# Agent adapters for the leaderboard. Each function runs ONE request in the
# current folder, non-interactively, allowed to edit files there, and writes the
# agent's own output to stdout. $1 = the request, $2 = the environment note.
#
# Every request starts a fresh session in the same folder (the project on disk
# carries over between requests). That is the one mode every agent supports,
# so no agent gets extra memory the others don't.
#
# Status: claude-code is the adapter the published results were produced with.
# The others follow each tool's documented non-interactive mode but have NOT
# been run by us yet; check the flags against your installed version first and
# send a correction if one is off.

agent_claude_code() {   # Claude Code; MODEL=claude-sonnet-5 etc.
  claude -p "$1" --append-system-prompt "$2" --output-format json --max-turns 40 \
    --permission-mode acceptEdits --allowedTools Read Write Edit Glob Grep --strict-mcp-config \
    ${MODEL:+--model "$MODEL"}
}

agent_codex() {         # OpenAI Codex CLI (untested adapter)
  codex exec --full-auto --skip-git-repo-check ${MODEL:+-m "$MODEL"} "$2

$1"
}

agent_gemini_cli() {    # Google Gemini CLI (untested adapter)
  gemini ${MODEL:+-m "$MODEL"} --yolo -p "$2

$1"
}

agent_aider() {         # Aider (untested adapter); it only edits files it is given or creates
  aider --yes-always --no-git --no-auto-commits ${MODEL:+--model "$MODEL"} --message "$2

$1"
}

agent_cursor() {        # Cursor CLI (untested adapter)
  cursor-agent -p --force ${MODEL:+--model "$MODEL"} "$2

$1"
}
