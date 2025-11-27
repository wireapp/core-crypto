#!/usr/bin/env sh

# Fail on first error
set -e

echo "Installing application" >&2
adb install app/build/outputs/apk/debug/app-debug.apk

# wait for device to be ready
adb wait-for-device

echo "Emulator booted" >&2

EMULATOR_ID=`adb get-serialno`
echo $EMULATOR_ID
