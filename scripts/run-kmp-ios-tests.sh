#!/usr/bin/env bash
# Runs the Kotlin/Native test executable of the KMP package on a new iOS simulator device.
#
# Kotlin/Native would run the executable on its own, but opening a database on iOS uses the
# keychain, which only apps can access. So this wraps it in an app first.
#
# Usage: run-kmp-ios-tests.sh <test.kexe> [test arguments, e.g. --ktest_filter=...]
set -euo pipefail

if [ $# -eq 0 ]; then
	echo "Usage: $0 <test.kexe> [test arguments]" >&2
	exit 1
fi

scripts=$(realpath "$(dirname "$0")")
test_executable=$(realpath "$1")
shift
host="$scripts/../crypto-ffi/bindings/kmp/ios-test-host"
bundle_id=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$host/Info.plist")
executable_name=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$host/Info.plist")

simulator_id=$("$scripts/create-ios-sim-device.sh" "iPhone 16 test-kmp")
work_dir=$(mktemp -d)
trap 'echo "deleting simulator device $simulator_id";
        "$scripts/delete-ios-sim-device.sh" "$simulator_id";
        rm -rf "$work_dir"' EXIT

# The entitlements are already linked into the executable; the simulator takes them from there.
app="$work_dir/$executable_name.app"
mkdir "$app"
cp "$host/Info.plist" "$app/"
cp "$test_executable" "$app/$executable_name"

# Boots the device and waits until it is ready.
xcrun simctl bootstatus "$simulator_id" -b
xcrun simctl install "$simulator_id" "$app"

# `simctl launch` waits for the app to exit, but always exits with 0 itself, so the result comes
# from the test runner's output. A crash ends it before the summary line.
log="$work_dir/test.log"
xcrun simctl launch --console-pty "$simulator_id" "$bundle_id" "$@" | tee "$log"

if ! grep -q '^\[==========\] .* ran\.' "$log"; then
	echo "The tests didn't run to completion." >&2
	exit 1
fi
if grep -q '^\[  FAILED  \]' "$log"; then
	exit 1
fi
