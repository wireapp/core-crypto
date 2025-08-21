#!/bin/bash

NAME="$1"

UDID=$(xcrun simctl create "$NAME" \
        com.apple.CoreSimulator.SimDeviceType.iPhone-16 \
        com.apple.CoreSimulator.SimRuntime.iOS-18-6)

echo "$UDID"
