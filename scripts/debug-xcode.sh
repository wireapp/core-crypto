#!/usr/bin/env bash
set -uo pipefail

OUTPUT=$(mktemp)

# Print the command being run
echo "==== Running command: $* ====\n"

# Run wrapped command, capture both output and status
"$@" 2>&1 | tee "$OUTPUT"
STATUS=${PIPESTATUS[0]}

# Try to find the xcodebuild log path
LOGFILE=$(grep -oE '/.*/xcodebuild-[A-F0-9-]+\.log' "$OUTPUT" | tail -1 )

if [[ $STATUS -ne 0 ]]; then
  echo "\n Command failed (exit code $STATUS).\n"

  if [[ -f "$LOGFILE" ]]; then
    echo "==== Printing full xcodebuild log: $LOGFILE ====\n"
    cat "$LOGFILE"
    echo "================================================"
  else
    echo "Could not find xcodebuild log file path in output."
  fi
fi

exit $STATUS
