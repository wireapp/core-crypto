#!/usr/bin/env bash
# Run the e2e interop test against apps that are already built. This installs
# them on a fresh emulator and, on macOS, a fresh simulator, but doesn't build
# anything; `make interop-test` builds what's missing first.
#
# INTEROP_APK must point at the Android interop app and, on macOS,
# INTEROP_IOS_APP at the iOS interop app. The make targets set both.

# pipefail matters: without it, a failure in `start-android-emulator.sh` is
# hidden behind `tee`'s exit status and we carry on with no emulator.
set -eo pipefail
scripts="$(realpath "$(dirname "$0")")"
cd "$scripts"

# The app install, the interop binary and our cleanup all talk to adb, so they
# need the same server port as the emulator.
# shellcheck disable=SC1091
source "$scripts/adb-env.sh"

: "${INTEROP_APK:?must point at the Android interop app}"

OS="$(uname -s)"

cleanup() {
  if [ -n "$simulator_id" ]; then
    echo "deleting simulator device $simulator_id"
    "$scripts/delete-ios-sim-device.sh" "$simulator_id"
  fi

  "$scripts/delete-android-emulator.sh"
}

trap cleanup EXIT

if [ "$OS" = "Darwin" ]; then
    : "${INTEROP_IOS_APP:?must point at the iOS interop app}"

    simulator_id="$("$scripts/create-ios-sim-device.sh" "iPhone 16 e2e-interop-test")"
    # Make the interop binary drive this simulator. Without it, it falls back to
    # whichever simulator is booted, which may not be ours.
    export INTEROP_SIMULATOR_DEVICE="$simulator_id"

    ../interop/src/clients/InteropClient/install-interop-client.sh "$simulator_id" "$INTEROP_IOS_APP"
fi


# We want to extract ADB_DEVICE from the script output, but
# we also want to get immediate prints on the console, as the
# script is running, so use tee to copy stdout to stderr.
script_stdout="$(./start-android-emulator.sh | tee /dev/stderr)"
eval "$(printf "%s" "$script_stdout" | grep '^ADB_DEVICE=')"
export ADB_DEVICE

echo "Installing $INTEROP_APK"
adb -s "$ADB_DEVICE" install -r "$INTEROP_APK"

cd "$scripts/.."

./target/debug/interop
