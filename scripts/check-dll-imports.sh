#!/usr/bin/env bash
# Fails if a Windows DLL imports a MinGW runtime library (libgcc_s_seh-1.dll, libwinpthread-1.dll,
# libstdc++-6.dll, …), which would have to be shipped next to it. Their names start with "lib",
# unlike those of the Windows system DLLs.
#
#   scripts/check-dll-imports.sh <dll>
set -euo pipefail

dll="$1"
imports="$(x86_64-w64-mingw32-objdump -p "$dll" | awk '/DLL Name:/ {print $3}' | sort -uf)"
if runtime="$(grep -iE '^lib' <<<"$imports")"; then
  echo "$dll imports MinGW runtime libraries: $(echo "$runtime" | tr '\n' ' ')" >&2
  exit 1
fi
echo "$dll imports only: $(echo "$imports" | tr '\n' ' ')"
