#!/usr/bin/env sh

DEVICE=$1

xcrun simctl shutdown $DEVICE
xcrun simctl delete $DEVICE
