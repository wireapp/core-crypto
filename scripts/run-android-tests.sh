#!/usr/bin/env bash
set -e
cd $(realpath $(dirname $0))

if [[ "${GITHUB_ACTIONS}" == "true" ]]; then
    sh ./setup-android-emulator.sh
fi

./start-android-emulator.sh

trap '
  echo "Shutting down Android emulator via adb"
  $ANDROID_HOME/platform-tools/adb emu kill
' EXIT

cd ../crypto-ffi/bindings

./gradlew android:connectedAndroidTest --rerun
