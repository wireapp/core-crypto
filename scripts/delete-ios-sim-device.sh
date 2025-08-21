#!/bin/bash

UDID="$1"

# Delete the simulator
xcrun simctl delete "$UDID"

# Clean up logs and device data
rm -rf ~/Library/Logs/CoreSimulator/"$UDID"
rm -rf ~/Library/Developer/CoreSimulator/Devices/"$UDID"
