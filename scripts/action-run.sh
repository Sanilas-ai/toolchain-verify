#!/usr/bin/env bash
# Run toolchain-verify with the composite-action inputs.
set -euo pipefail

BIN="${TV_BIN:?missing TV_BIN}"
CMD="${INPUT_COMMAND:-scan}"
PATH_ARG="${INPUT_PATH:-.}"
FORMAT="${INPUT_FORMAT:-sarif}"
FAIL_ON="${INPUT_FAIL_ON:-fail}"
EXTRA="${INPUT_ARGS:-}"
WORKDIR="${INPUT_WORKDIR:-.}"

cd "$WORKDIR"
REPORT=""
ARGS=()

case "$CMD" in
  scan|agent|exec-lint|models)
    # path-taking commands
    ;;
esac

# Format flags for scan / mcp-tools
FORMAT_FLAG=()
case "$FORMAT" in
  sarif) FORMAT_FLAG=(--sarif); REPORT="${RUNNER_TEMP:-/tmp}/toolchain-verify.sarif" ;;
  json)  FORMAT_FLAG=(--json);  REPORT="${RUNNER_TEMP:-/tmp}/toolchain-verify.json" ;;
  text|"") FORMAT_FLAG=(); REPORT="" ;;
  *) echo "unknown format: $FORMAT" >&2; exit 2 ;;
esac

# fail-on → CLI flags
STRICT=()
case "$FAIL_ON" in
  fail) ;;
  warn) STRICT=(--strict) ;;
  never) ;;
  *) echo "unknown fail-on: $FAIL_ON" >&2; exit 2 ;;
esac

# shellcheck disable=SC2206
EXTRA_ARR=( $EXTRA )

set +e
case "$CMD" in
  scan)
    if [ -n "$REPORT" ]; then
      "$BIN" scan "${FORMAT_FLAG[@]}" "${STRICT[@]}" "${EXTRA_ARR[@]}" "$PATH_ARG" > "$REPORT"
      rc=$?
    else
      "$BIN" scan "${STRICT[@]}" "${EXTRA_ARR[@]}" "$PATH_ARG"
      rc=$?
    fi
    ;;
  mcp-tools)
    if [ -n "$REPORT" ]; then
      "$BIN" mcp-tools "${FORMAT_FLAG[@]}" "${STRICT[@]}" "${EXTRA_ARR[@]}" "$PATH_ARG" > "$REPORT"
      rc=$?
    else
      "$BIN" mcp-tools "${STRICT[@]}" "${EXTRA_ARR[@]}" "$PATH_ARG"
      rc=$?
    fi
    ;;
  agent|protect|docker|host|check|models|exec-lint|pin|init|version|policy)
    # Generic: command + optional path + extra args. Format only if supported.
    if [ "$CMD" = "agent" ] || [ "$CMD" = "protect" ] || [ "$CMD" = "docker" ] || [ "$CMD" = "host" ] || [ "$CMD" = "models" ] || [ "$CMD" = "exec-lint" ]; then
      if [ "$FORMAT" = "json" ]; then
        REPORT="${RUNNER_TEMP:-/tmp}/toolchain-verify.json"
        "$BIN" "$CMD" --json "${STRICT[@]}" "${EXTRA_ARR[@]}" ${PATH_ARG:+$PATH_ARG} > "$REPORT"
        rc=$?
      else
        "$BIN" "$CMD" "${STRICT[@]}" "${EXTRA_ARR[@]}" ${PATH_ARG:+$PATH_ARG}
        rc=$?
      fi
    else
      "$BIN" "$CMD" "${EXTRA_ARR[@]}"
      rc=$?
    fi
    ;;
  *)
    echo "unsupported command: $CMD" >&2
    exit 2
    ;;
esac
set -e

verdict="UNKNOWN"
if [ -n "$REPORT" ] && [ -f "$REPORT" ]; then
  if command -v jq >/dev/null 2>&1 && [[ "$REPORT" == *.json ]]; then
    verdict=$(jq -r '.verdict // .Verdict // empty' "$REPORT" 2>/dev/null || true)
  fi
  # SARIF / text: derive from exit code
fi
if [ -z "$verdict" ] || [ "$verdict" = "UNKNOWN" ]; then
  case "$rc" in
    0) verdict=PASS ;;
    1) verdict=FAIL ;;
    4) verdict=INCOMPLETE ;;
    *) verdict=ERROR ;;
  esac
fi

if [ -n "$REPORT" ] && [ -s "$REPORT" ]; then
  echo "report-path=$REPORT" >> "$GITHUB_OUTPUT"
else
  echo "report-path=" >> "$GITHUB_OUTPUT"
  REPORT=""
fi
echo "verdict=$verdict" >> "$GITHUB_OUTPUT"
echo "toolchain-verify exit=$rc verdict=$verdict report=${REPORT:-none}"

case "$FAIL_ON" in
  never)
    # Surface usage errors only.
    if [ "$rc" -eq 2 ]; then exit 2; fi
    exit 0
    ;;
  warn|fail)
    exit "$rc"
    ;;
esac
