#!/usr/bin/env bash
set -e

./scripts/create-android-virtual-device.sh

trap '
  echo "Shutting down Android emulator via adb"
  $ANDROID_HOME/platform-tools/adb emu kill
' EXIT

cd crypto-ffi/bindings

./gradlew android:connectedAndroidTest --rerun
