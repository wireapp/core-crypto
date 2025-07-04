#!/usr/bin/env sh

DEVICE=$1

xcrun simctl shutdown $DEVICE
xcrun simctl delete $DEVICE

rm -rf ~/Library/Logs/CoreSimulator/$DEVICE
rm -rf ~/Library/Developer/CoreSimulator/Devices/$DEVICE
