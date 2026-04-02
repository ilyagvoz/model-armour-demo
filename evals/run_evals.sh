#!/usr/bin/env bash
# Model Armor Eval Wizard — interactive guide for running the eval suite.
# Run from anywhere: the script resolves the project root automatically.

set -euo pipefail

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Colours ────────────────────────────────────────────────────────────────────
BOLD=$'\033[1m'
DIM=$'\033[2m'
CYAN=$'\033[0;36m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
RESET=$'\033[0m'

# ── Helpers ────────────────────────────────────────────────────────────────────
hr()     { printf '%s%s%s\n' "$DIM" "──────────────────────────────────────────────────" "$RESET"; }
title()  { printf '\n%s%s%s\n\n' "$BOLD$CYAN" "$1" "$RESET"; }
label()  { printf '%s%s%s ' "$BOLD" "$1" "$RESET"; }
hint()   { printf '%s%s%s\n' "$DIM" "$1" "$RESET"; }
ok()     { printf '%s✓ %s%s\n' "$GREEN" "$1" "$RESET"; }
warn()   { printf '%s⚠  %s%s\n' "$YELLOW" "$1" "$RESET"; }
die()    { printf '%s✗  %s%s\n' "$RED" "$1" "$RESET" >&2; exit 1; }

# Read a single choice from a numbered menu.
# Usage: pick RESULT_VAR "prompt" val1 val2 ...
pick() {
  local -n _ref=$1; shift
  local prompt="$1"; shift
  local options=("$@")
  local n="${#options[@]}"
  local i choice

  for (( i=0; i<n; i++ )); do
    printf '  %s%d)%s %s\n' "$BOLD" "$((i+1))" "$RESET" "${options[$i]}"
  done
  echo
  while true; do
    label "$prompt"
    read -r choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= n )); then
      _ref="${options[$((choice-1))]}"
      return
    fi
    warn "Enter a number between 1 and $n."
  done
}

# Read a yes/no question. Default is supplied as 'y' or 'n'.
yn() {
  local prompt="$1"
  local default="${2:-n}"
  local display
  if [[ "$default" == "y" ]]; then display="[Y/n]"; else display="[y/N]"; fi
  label "$prompt $display:"
  read -r ans
  ans="${ans:-$default}"
  [[ "${ans,,}" == "y" ]]
}

# ── Sanity checks ──────────────────────────────────────────────────────────────
if ! python3 -c "import modelarmor_v1" &>/dev/null; then
  die "google-cloud-modelarmor not installed. Run: python3 -m pip install -r requirements.txt --index-url https://pypi.org/simple/"
fi
if [[ ! -f .env ]]; then
  warn ".env not found. Copy .env.example and fill in GCP_PROJECT_ID."
fi

# ── Header ─────────────────────────────────────────────────────────────────────
clear
printf '\n'
printf '%s╔══════════════════════════════════════════════════╗%s\n' "$BOLD$CYAN" "$RESET"
printf '%s║     Model Armor — Eval Wizard                    ║%s\n' "$BOLD$CYAN" "$RESET"
printf '%s╚══════════════════════════════════════════════════╝%s\n' "$BOLD$CYAN" "$RESET"
printf '\n'
hint "Tests your Model Armor templates against 38 labelled cases (good/bad/edge)"
hint "and reports precision, recall, F1, and false positives on legitimate content."
printf '\n'

# ── Step 1: Mode ───────────────────────────────────────────────────────────────
hr
title "Step 1 — Choose a mode"

MODE_LABELS=(
  "Single preset    — run one named config and see per-case results"
  "Compare presets  — run multiple configs side-by-side and get a recommendation"
  "Existing template — test a template already deployed in your GCP project"
)
pick MODE_KEY "Mode" "${MODE_LABELS[@]}"

case "$MODE_KEY" in
  "Single preset"*)    MODE="single"   ;;
  "Compare presets"*)  MODE="compare"  ;;
  "Existing template"*) MODE="template" ;;
esac

# ── Step 2: Config / template selection ────────────────────────────────────────
hr
PRESET_NAMES=("strict" "moderate" "permissive" "prompt-only")

PRESET_LABELS=(
  "strict       — All filters at MEDIUM_AND_ABOVE, full SDP (14 types incl. PERSON_NAME)"
  "moderate     — PI+URI on, RAI at HIGH, credentials-only SDP  ${BOLD}★ recommended${RESET}"
  "permissive   — SEXUALLY_EXPLICIT only; no PI, URI, or SDP"
  "prompt-only  — Full prompt protection, SDP without PERSON_NAME (mirrors Gemini Enterprise)"
)

SELECTED_PRESETS=()
TEMPLATE_NAME=""
TEMPLATE_REGION=""

if [[ "$MODE" == "single" ]]; then
  title "Step 2 — Choose a preset"
  pick PRESET_CHOICE "Preset" "${PRESET_LABELS[@]}"
  # Extract the preset name (first word before spaces/dashes)
  SINGLE_PRESET="${PRESET_CHOICE%% *}"
  SELECTED_PRESETS=("$SINGLE_PRESET")

elif [[ "$MODE" == "compare" ]]; then
  title "Step 2 — Choose presets to compare"
  hint "Enter numbers separated by spaces, or press Enter to compare all four."
  printf '\n'
  for i in "${!PRESET_LABELS[@]}"; do
    printf '  %s%d)%s %s\n' "$BOLD" "$((i+1))" "$RESET" "${PRESET_LABELS[$i]}"
  done
  printf '\n'
  label "Presets [default: all]:"
  read -r PRESET_INPUT

  if [[ -z "$PRESET_INPUT" ]]; then
    SELECTED_PRESETS=("${PRESET_NAMES[@]}")
  else
    for token in $PRESET_INPUT; do
      if [[ "$token" =~ ^[1-4]$ ]]; then
        SELECTED_PRESETS+=("${PRESET_NAMES[$((token-1))]}")
      else
        warn "Ignoring invalid selection: $token"
      fi
    done
    if [[ ${#SELECTED_PRESETS[@]} -eq 0 ]]; then
      warn "No valid presets selected, defaulting to all."
      SELECTED_PRESETS=("${PRESET_NAMES[@]}")
    fi
  fi

elif [[ "$MODE" == "template" ]]; then
  title "Step 2 — Existing template"
  label "Template ID (e.g. demo-template-prompt):"
  read -r TEMPLATE_NAME
  [[ -z "$TEMPLATE_NAME" ]] && die "Template ID cannot be empty."

  # Determine default region from .env
  DEFAULT_MA_REGION="us-central1"
  if [[ -f .env ]]; then
    _ma=$(grep -E '^MODEL_ARMOR_REGION=' .env | cut -d= -f2 || true)
    _gcp=$(grep -E '^GCP_REGION=' .env | cut -d= -f2 || true)
    DEFAULT_MA_REGION="${_ma:-${_gcp:-us-central1}}"
  fi

  label "Region [$DEFAULT_MA_REGION]:"
  read -r TEMPLATE_REGION
  TEMPLATE_REGION="${TEMPLATE_REGION:-$DEFAULT_MA_REGION}"
fi

# ── Step 3: Category filter ────────────────────────────────────────────────────
hr
title "Step 3 — Filter by category"
hint "Which test cases should run?"
printf '\n'
printf '  %s1)%s all    — All 38 cases (good + bad + edge)\n' "$BOLD" "$RESET"
printf '  %s2)%s good   — 13 legitimate enterprise prompts (must-pass)\n' "$BOLD" "$RESET"
printf '  %s3)%s bad    — 14 malicious inputs (must-block)\n' "$BOLD" "$RESET"
printf '  %s4)%s edge   — 11 false-positive canaries (should pass)\n' "$BOLD" "$RESET"
printf '  %s5)%s custom — Pick a subset (space-separated: good bad edge)\n' "$BOLD" "$RESET"
printf '\n'
label "Category [default: all]:"
read -r CAT_INPUT
CAT_FLAGS=()

case "${CAT_INPUT:-1}" in
  1|all|"") ;;
  2|good)   CAT_FLAGS=("--category" "good") ;;
  3|bad)    CAT_FLAGS=("--category" "bad") ;;
  4|edge)   CAT_FLAGS=("--category" "edge") ;;
  5|custom)
    label "Categories (e.g. good edge):"
    read -r CUSTOM_CATS
    for c in $CUSTOM_CATS; do
      CAT_FLAGS+=("--category" "$c")
    done
    ;;
  *)
    # Allow typing category names directly at the first prompt too
    for c in $CAT_INPUT; do
      CAT_FLAGS+=("--category" "$c")
    done
    ;;
esac

# ── Step 4: Direction filter ───────────────────────────────────────────────────
hr
title "Step 4 — Filter by direction"
hint "Scan direction to test:"
printf '\n'
printf '  %s1)%s all      — Prompt and response cases\n' "$BOLD" "$RESET"
printf '  %s2)%s prompt   — User input scanning only\n' "$BOLD" "$RESET"
printf '  %s3)%s response — Model output scanning only\n' "$BOLD" "$RESET"
printf '\n'
label "Direction [default: all]:"
read -r DIR_INPUT
DIR_FLAGS=()

case "${DIR_INPUT:-1}" in
  1|all|"") ;;
  2|prompt)   DIR_FLAGS=("--direction" "prompt") ;;
  3|response) DIR_FLAGS=("--direction" "response") ;;
esac

# ── Step 5: Output format ──────────────────────────────────────────────────────
hr
title "Step 5 — Output format"
printf '  %s1)%s table  — Rich formatted console output %s(default)%s\n' "$BOLD" "$RESET" "$DIM" "$RESET"
printf '  %s2)%s json   — Machine-readable JSON\n' "$BOLD" "$RESET"
printf '\n'
label "Format [default: table]:"
read -r FMT_INPUT
OUTPUT_FLAGS=()

case "${FMT_INPUT:-1}" in
  2|json) OUTPUT_FLAGS=("--output" "json") ;;
  *)      ;;
esac

# ── Step 6: Save to file ───────────────────────────────────────────────────────
hr
SAVE_FLAGS=()
if yn "Step 6 — Save results to a file?" n; then
  printf '\n'
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  DEFAULT_FILE="evals/results_${TIMESTAMP}.json"
  label "File path [default: $DEFAULT_FILE]:"
  read -r SAVE_PATH
  SAVE_PATH="${SAVE_PATH:-$DEFAULT_FILE}"
  SAVE_FLAGS=("--output" "json" "--save" "$SAVE_PATH")
  OUTPUT_FLAGS=()  # --save implies json
fi

# ── Build command ──────────────────────────────────────────────────────────────
CMD=("python3" "evals/eval_suite.py")

if [[ "$MODE" == "single" ]]; then
  CMD+=("--config" "${SELECTED_PRESETS[0]}")
elif [[ "$MODE" == "compare" ]]; then
  CMD+=("--compare" "$(IFS=,; echo "${SELECTED_PRESETS[*]}")")
elif [[ "$MODE" == "template" ]]; then
  CMD+=("--template" "$TEMPLATE_NAME" "--region" "$TEMPLATE_REGION")
fi

CMD+=("${CAT_FLAGS[@]}" "${DIR_FLAGS[@]}" "${OUTPUT_FLAGS[@]}" "${SAVE_FLAGS[@]}")

# ── Estimate ───────────────────────────────────────────────────────────────────
CASE_COUNT=38
if [[ ${#CAT_FLAGS[@]} -gt 0 ]]; then
  # Rough per-category counts: good=13, bad=14, edge=11
  CASE_COUNT=0
  for flag in "${CAT_FLAGS[@]}"; do
    case "$flag" in
      good)  (( CASE_COUNT+=13 )) ;;
      bad)   (( CASE_COUNT+=14 )) ;;
      edge)  (( CASE_COUNT+=11 )) ;;
    esac
  done
  [[ $CASE_COUNT -eq 0 ]] && CASE_COUNT=38
fi
if [[ ${#DIR_FLAGS[@]} -gt 0 ]]; then
  # ~15% of cases are response-direction
  CASE_COUNT=$(( CASE_COUNT * 85 / 100 ))
fi

NUM_RUNS=${#SELECTED_PRESETS[@]}
[[ "$MODE" == "template" ]] && NUM_RUNS=1
TOTAL_CALLS=$(( CASE_COUNT * NUM_RUNS ))
EST_SECS=$(( TOTAL_CALLS / 2 + NUM_RUNS * 5 ))  # 0.5s delay + template create overhead
EST_LABEL=""
if (( EST_SECS < 60 )); then
  EST_LABEL="${EST_SECS}s"
else
  EST_LABEL="$(( EST_SECS / 60 ))m $(( EST_SECS % 60 ))s"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
hr
printf '\n%s  Ready to run%s\n\n' "$BOLD" "$RESET"

if [[ "$MODE" == "single" ]]; then
  printf '  Mode:     Single preset — %s%s%s\n' "$BOLD" "${SELECTED_PRESETS[0]}" "$RESET"
elif [[ "$MODE" == "compare" ]]; then
  printf '  Mode:     Compare — %s%s%s\n' "$BOLD" "$(IFS=', '; echo "${SELECTED_PRESETS[*]}")" "$RESET"
elif [[ "$MODE" == "template" ]]; then
  printf '  Mode:     Existing template — %s%s%s (region: %s)\n' "$BOLD" "$TEMPLATE_NAME" "$RESET" "$TEMPLATE_REGION"
fi

CAT_DESC="all (good + bad + edge)"
[[ ${#CAT_FLAGS[@]} -gt 0 ]] && CAT_DESC="${CAT_FLAGS[*]//--category /}"
printf '  Cases:    %s\n' "$CAT_DESC"

DIR_DESC="all (prompt + response)"
[[ ${#DIR_FLAGS[@]} -gt 0 ]] && DIR_DESC="${DIR_FLAGS[1]}"
printf '  Direction:%s\n' " $DIR_DESC"

printf '  API calls:~%d   Estimated time: %s\n' "$TOTAL_CALLS" "$EST_LABEL"

if [[ ${#SAVE_FLAGS[@]} -gt 0 ]]; then
  printf '  Save to:  %s\n' "$SAVE_PATH"
fi

printf '\n%s' "$DIM"
printf '  Command: %s\n' "${CMD[*]}"
printf '%s\n' "$RESET"
hr

printf '\nPress %sEnter%s to run, or %sCtrl+C%s to cancel...' "$BOLD" "$RESET" "$BOLD" "$RESET"
read -r

# ── Run ────────────────────────────────────────────────────────────────────────
printf '\n'
"${CMD[@]}"
EXIT_CODE=$?

printf '\n'
hr
if [[ $EXIT_CODE -eq 0 ]]; then
  ok "Done."
  if [[ ${#SAVE_FLAGS[@]} -gt 0 ]]; then
    ok "Results saved to: $SAVE_PATH"
  fi
else
  warn "eval_suite.py exited with code $EXIT_CODE"
fi
