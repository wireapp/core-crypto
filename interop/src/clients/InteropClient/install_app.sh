#!/usr/bin/env sh

DEVICE=$1

xcrun simctl boot "$DEVICE"
xcrun simctl install booted Products/Applications/InteropClient.app
