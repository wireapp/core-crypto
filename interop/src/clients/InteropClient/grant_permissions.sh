#!/usr/bin/env sh

DEVICE=$1

# Pre-approve opening URLs in InteropClient to suppress permission dialogs
SIM_DATA_PATH=`xcrun simctl get_app_container booted com.wire.InteropClient | sed 's/\(.*data\).*/\1/'`
PLIST_PATH="$SIM_DATA_PATH/Library/Preferences/com.apple.launchservices.schemeapproval.plist"
/usr/libexec/PlistBuddy -c 'Add :com.apple.CoreSimulator.CoreSimulatorBridge-->interop string "com.wire.InteropClient"' $PLIST_PATH

# Restart the simulator for changes to take effect
xcrun simctl shutdown all
xcrun simctl boot "$DEVICE"
