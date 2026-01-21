#!/usr/bin/env bash
set -e
scripts=$(realpath $(dirname $0))
cd $scripts

TARGET_NAME=$1

OS="$(uname -s)"

cleanup() {
  if [ -n "$simulator_id" ]; then
    echo "deleting simulator device $simulator_id"
    $scripts/delete-ios-sim-device.sh "$simulator_id"
  fi

  echo "Shutting down Android emulator via adb"
  adb -s $ADB_DEVICE emu kill
}

trap cleanup EXIT

if [ "$OS" = "Darwin" ]; then
    simulator_id=$($scripts/create-ios-sim-device.sh "iPhone 16 e2e-interop-test")

    cd ../interop/src/clients/InteropClient

    xcodebuild \
    	-scheme InteropClient \
    	-configuration "$TARGET_NAME" \
    	-sdk iphonesimulator \
    	-destination "id=$simulator_id" \
    	clean build install DSTROOT=./Products

    ./install-interop-client.sh $simulator_id

    cd $scripts
fi


# We want to extract ADB_DEVICE from the script output, but
# we also want to get immediate prints on the console, as the
# script is running, so use tee to copy stdout to stderr.
script_stdout=$(./start-android-emulator.sh | tee /dev/stderr)
eval $(printf "%s" "$script_stdout" | grep '^ADB_DEVICE=')
export ADB_DEVICE

cd ../interop/src/clients

./gradlew android-interop:install$TARGET_NAME

cd $scripts/..

./target/debug/interop
