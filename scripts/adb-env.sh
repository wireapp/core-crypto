# shellcheck shell=bash
#
# Source this file; don't run it. It sets up the environment for the scripts
# that drive an Android emulator.
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
# The emulator ports (27000 + uid, see `start-android-emulator.sh`) don't
# overlap this range.
#
# Outside CI we keep the default port, so a local emulator stays visible to
# Android Studio and any adb already running.
if [ -z "${ANDROID_ADB_SERVER_PORT-}" ] && [ "${GITHUB_ACTIONS-}" = true ]; then
    ANDROID_ADB_SERVER_PORT=$((15000 + $(id -u)))
    export ANDROID_ADB_SERVER_PORT
fi
