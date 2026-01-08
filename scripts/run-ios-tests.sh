#!/usr/bin/env bash
set -e

XCODE_CONFIG=$1

simulator_id=$(./scripts/create-ios-sim-device.sh "iPhone 16 test-ios")

trap 'echo "deleting simulator device $simulator_id";
        ../../../../scripts/delete-ios-sim-device.sh "$simulator_id"' EXIT

cd crypto-ffi/bindings/swift/WireCoreCrypto

xcodebuild test \
	-scheme TestHost \
	-configuration "$XCODE_CONFIG" \
	-sdk iphonesimulator \
	-destination "id=$simulator_id"
