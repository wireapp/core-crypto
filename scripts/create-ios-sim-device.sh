#!/bin/bash
set -e

NAME="$1"

UDID=$(xcrun simctl create "$NAME" \
        com.apple.CoreSimulator.SimDeviceType.iPhone-16 \
        com.apple.CoreSimulator.SimRuntime.iOS-27-2)

echo "$UDID"
