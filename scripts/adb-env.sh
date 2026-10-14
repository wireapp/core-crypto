# shellcheck shell=bash
# The variables set here are used by the scripts that source this file.
# shellcheck disable=SC2034
#
# Source this file; don't run it. It sets up the environment for the scripts
# that drive an Android emulator, and holds the settings that the scripts which
# start and delete the emulator must agree on.

# Put the Android SDK tools on the PATH.
export PATH="${ANDROID_HOME:?ANDROID_HOME must be set}/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

if [ "${RUNNER_ENVIRONMENT-}" = github-hosted ]; then
    # For some reason avdmanager on github runners puts newly created AVDs under
    # the following dir. So point ANDROID_AVD_HOME to it so the emulator can find
    # the AVD.
    export ANDROID_AVD_HOME=~/.config/.android/avd
fi

# The name of the Android Virtual Device we're going to use.
AVD_NAME=test-phone

# Choose a port for the emulator to use to communicate with adb (Android
# debugger). Several runner users share each of our self-hosted machines, and
# outside CI they may also share an adb server (see below), so the port is based
# on the current user's ID to keep their emulators apart.
EMULATOR_PORT=$((27000 + $(id -u)))
ADB_DEVICE=emulator-$EMULATOR_PORT

# The adb server
#
# By default there is one adb server per machine, listening on tcp:5037. Our
# self-hosted macOS runners each run several runner users side by side, so that
# server ends up shared by every concurrent job on the machine. GitHub kills the
# processes a job started when that job ends, and that includes the adb server,
# if that job happened to be the one which started it. Every other job on the
# machine then loses its emulator.
#
# On CI we therefore give each user their own adb server on its own port. adb,
# the emulator and the Android Gradle plugin all read ANDROID_ADB_SERVER_PORT,
# so exporting it here is enough, as long as it happens before any of them run.
# The emulator ports (27000 + uid, above) don't overlap this range.
#
# Outside CI we keep the default port, so a local emulator stays visible to
# Android Studio and any adb already running.
if [ -z "${ANDROID_ADB_SERVER_PORT-}" ] && [ "${GITHUB_ACTIONS-}" = true ]; then
    ANDROID_ADB_SERVER_PORT=$((15000 + $(id -u)))
    export ANDROID_ADB_SERVER_PORT
fi
