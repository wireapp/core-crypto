#!/usr/bin/env bash

set -euo pipefail

# Sets AVD_NAME, EMULATOR_PORT and ADB_DEVICE, and the PATH for the SDK tools.
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/adb-env.sh"

# The system image the AVD is built from. Keep this in line with what
# `setup-android-emulator.sh` installs.
ANDROID_API_LEVEL=32
case "$(uname -s)" in
    Darwin) ANDROID_ARCH=arm64-v8a ;;
    Linux) ANDROID_ARCH=x86_64 ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
SYSTEM_IMAGE="system-images;android-$ANDROID_API_LEVEL;default;$ANDROID_ARCH"

# Make sure that the adb server is running before starting the emulator,
# otherwise the emulator will not start correctly. If it's already running,
# this does nothing.
#
# The server is meant to outlive this job, so the next job on this runner
# doesn't have to start it again. GitHub kills every process that carries the
# job's RUNNER_TRACKING_ID when the job ends, and the server inherits our
# environment, so clear that variable to keep the server out of the cleanup.
#
# This has to come before any other adb command: those start a server too if
# none is running, and that one would not escape the cleanup.
RUNNER_TRACKING_ID="" adb start-server

# If there's an emulator instance running with our AVD, shut it down first. It
# would hold the AVD we're about to recreate.
if [ "$(adb -s "$ADB_DEVICE" emu avd name 2>/dev/null | head -n1 | sed 's/[[:space:]]*$//')" = "$AVD_NAME" ]; then
    echo An emulator is already running. Going to shut it down.
    adb -s "$ADB_DEVICE" emu kill
fi

# Recreate the AVD on every run, even if it exists. That gives every run the
# same fresh device, built from the image above rather than from whatever an
# earlier run left behind.
#
# Don't use `grep -q` here: it would exit at the first match, and pipefail would
# then report sdkmanager's SIGPIPE as a failure.
if ! sdkmanager --list_installed 2>/dev/null | cut -f1 -d'|' | tr -d ' ' | grep -xF "$SYSTEM_IMAGE" >/dev/null; then
    echo "System image $SYSTEM_IMAGE is not installed. Install it with:" >&2
    echo "    sdkmanager --install '$SYSTEM_IMAGE'" >&2
    exit 1
fi
echo "Creating AVD $AVD_NAME using $SYSTEM_IMAGE..."
echo "no" | avdmanager create avd -n "$AVD_NAME" --package "$SYSTEM_IMAGE" --force

# Launch the emulator
echo "Launching emulator on $AVD_NAME..."
logfile="$(mktemp)"

# With the image's default userdata partition, the emulator refuses to boot
# unless 12 GiB of disk are free. Our test apps need very little space, so ask
# for a 2 GiB partition instead.
emulator -avd "$AVD_NAME" -port "$EMULATOR_PORT" -no-window -gpu swiftshader_indirect \
         -no-snapshot -noaudio -no-boot-anim -no-metrics -partition-size 2048 >"$logfile" 2>&1 &
EMULATOR_PID=$!

echo "Emulator log file: $logfile"

# How long to wait for the emulator to boot before giving up. A healthy cold
# boot takes between 15 and 80 seconds on our runners.
BOOT_TIMEOUT_SECONDS=${BOOT_TIMEOUT_SECONDS:-300}

# Print the emulator log and fail. Everything goes to stderr, because callers
# capture our stdout.
fail_boot() {
  echo "$1" >&2
  echo "--- emulator log ($logfile) ---" >&2
  cat "$logfile" >&2
  echo "--- end of emulator log ---" >&2
  kill "$EMULATOR_PID" 2>/dev/null || true
  exit 1
}

echo "Waiting up to ${BOOT_TIMEOUT_SECONDS}s for Android emulator to be fully booted..."

deadline=$((SECONDS + BOOT_TIMEOUT_SECONDS))
until [ "$(adb -s "$ADB_DEVICE" shell getprop sys.boot_completed 2>/dev/null | tr -d '[:space:]')" = 1 ]; do
  if ! kill -0 "$EMULATOR_PID" 2>/dev/null; then
    fail_boot "The emulator process exited before the device finished booting."
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    fail_boot "The emulator did not finish booting within ${BOOT_TIMEOUT_SECONDS}s."
  fi
  sleep 1
done

echo "Emulator started. PID: $EMULATOR_PID"

echo  "ADB_DEVICE=$ADB_DEVICE"
