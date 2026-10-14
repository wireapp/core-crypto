#!/usr/bin/env bash
# pipefail matters: without it, a failure in `start-android-emulator.sh` is
# hidden behind `tee`'s exit status and we carry on with no emulator.
set -eo pipefail
scripts="$(realpath "$(dirname "$0")")"
cd "$scripts"

# Gradle and our cleanup talk to adb, so they need the same server port as the
# emulator.
# shellcheck disable=SC1091
source ./adb-env.sh

if [[ "${GITHUB_ACTIONS}" == "true" ]]; then
    sh ./setup-android-emulator.sh
fi

# Set before starting the emulator, so that a failed start is cleaned up too.
trap '"$scripts/delete-android-emulator.sh"' EXIT

# We want to extract ADB_DEVICE from the script output, but
# we also want to get immediate prints on the console, as the
# script is running, so use tee to copy stdout to stderr.
script_stdout="$(./start-android-emulator.sh | tee /dev/stderr)"
eval "$(printf "%s" "$script_stdout" | grep '^ADB_DEVICE=')"

cd ../crypto-ffi/bindings

./gradlew android:connectedAndroidTest --rerun
