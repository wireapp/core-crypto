#!/usr/bin/env bash
# Shut down our Android emulator, if it's running, and delete its AVD.
#
# `start-android-emulator.sh` recreates the AVD on every run, so there's no
# reason to keep it afterwards, and its userdata partition takes gigabytes on
# runners that are shared by several users. This is safe to run when there's
# no emulator or no AVD, and it never fails: it's meant for cleanup, including
# after a cancelled job.

set -uo pipefail

# Sets AVD_NAME and ADB_DEVICE, and the PATH for the SDK tools.
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/adb-env.sh"

# The emulator runs as qemu with `-avd <name>` on its command line.
emulator_running() {
    pgrep -u "$(id -u)" -f -- "-avd $AVD_NAME" >/dev/null
}

if emulator_running; then
    echo "Shutting down Android emulator $ADB_DEVICE"
    adb -s "$ADB_DEVICE" emu kill >/dev/null 2>&1

    # Give it a moment to exit before we delete files it still has open.
    for _ in $(seq 1 15); do
        emulator_running || break
        sleep 1
    done
    if emulator_running; then
        echo "The emulator didn't exit; killing it"
        pkill -9 -u "$(id -u)" -f -- "-avd $AVD_NAME"
    fi
fi

echo "Deleting AVD $AVD_NAME"
avdmanager delete avd -n "$AVD_NAME" >/dev/null 2>&1
# In case avdmanager failed or left anything behind, remove the files directly.
avd_home="${ANDROID_AVD_HOME:-${ANDROID_USER_HOME:-$HOME/.android}/avd}"
rm -rf "${avd_home:?}/${AVD_NAME:?}.avd" "$avd_home/$AVD_NAME.ini"

exit 0
