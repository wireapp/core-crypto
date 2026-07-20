#!/usr/bin/env bash
set -euo pipefail

KEEP_TOOLCHAIN="$(rustup show active-toolchain | awk '{print $1}')"

rustup toolchain list | awk '{print $1}' | while read -r tc; do
  if [[ "$tc" != "$KEEP_TOOLCHAIN" ]]; then
    echo "Removing $tc"
    rustup toolchain uninstall "$tc" || {
      echo "::warning::Failed to uninstall $tc"
    }
  fi
done
