#!/usr/bin/env bash
set -e
cd $(realpath $(dirname $0))

if [[ "${GITHUB_ACTIONS}" == "true" ]]; then
    sh ./setup-android-emulator.sh
fi

./start-android-emulator.sh

cleanup() {
  echo "Shutting down Android emulator via adb"
  adb_device=emulator-$((27000 + $(id -u)))
  $ANDROID_HOME/platform-tools/adb -s $adb_device emu kill
}

trap cleanup EXIT

cd ../crypto-ffi/bindings

./gradlew android:connectedAndroidTest --rerun
