#!/usr/bin/env bash
set -e
cd $(realpath $(dirname $0))

if [[ "${GITHUB_ACTIONS}" == "true" ]]; then
    sh ./setup-android-emulator.sh
fi

# We want to extract ADB_DEVICE from the script output, but
# we also want to get immediate prints on the console, as the
# script is running, so use tee to copy stdout to stderr.
script_stdout=$(./start-android-emulator.sh | tee /dev/stderr)
eval $(printf "%s" "$script_stdout" | grep '^ADB_DEVICE=')

cleanup() {
  echo "Shutting down Android emulator via adb"
  $ANDROID_HOME/platform-tools/adb -s "$ADB_DEVICE" emu kill
}

trap cleanup EXIT

cd ../crypto-ffi/bindings

./gradlew android:connectedAndroidTest --rerun
