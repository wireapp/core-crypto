#!/usr/bin/env sh

# Fail on first error
set -e

SIMULATOR_NAME="Interop Simulator - `uuidgen`"
SIMULATOR_UDID=`xcrun simctl create "$SIMULATOR_NAME" "iPhone 16"`
echo "Creating new simulator" >&2
xcrun simctl boot $SIMULATOR_UDID
echo "Installing application" >&2
xcrun simctl install $SIMULATOR_UDID Products/Applications/InteropClient.app

# Pre-approve opening URLs in InteropClient to suppress permission dialogs
echo "Pre-approving opening URLs" >&2
SIM_DATA_PATH=`xcrun simctl get_app_container $SIMULATOR_UDID com.wire.InteropClient | sed 's/\(.*data\).*/\1/'`
PLIST_PATH="$SIM_DATA_PATH/Library/Preferences/com.apple.launchservices.schemeapproval.plist"
/usr/libexec/PlistBuddy -c 'Add :com.apple.CoreSimulator.CoreSimulatorBridge-->interop string "com.wire.InteropClient"' $PLIST_PATH 1>&2;

# Wait until application has finished installing before restarting simulator
sleep 2

# Restart the simulator for changes to take effect
echo "Restarting simulator" >&2
xcrun simctl shutdown $SIMULATOR_UDID
xcrun simctl boot $SIMULATOR_UDID

echo "Simulator booted" >&2
echo $SIMULATOR_UDID
