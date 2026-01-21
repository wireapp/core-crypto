set -euo pipefail

# The name of the Android Virtual Device we're going to use.
AVD_NAME=test-phone

# Choose a port for the emulator to use to communicate with adb (Android
# debugger). Since the adb server is system-wide, any user can see any other
# user's devices, which is a problem when running under CI, where there may be
# multiple jobs running at the same time, all using the same adb server, and
# therefore seeing the same emulator devices. To avoid that, just pick a port
# based on current user's ID.
PORT=$((27000 + $(id -u)))
ADB_DEVICE=emulator-$PORT

# PATH updates
export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH

# Create an AVD if it does not exist
if ! avdmanager list avd | grep -q "^Name: $AVD_NAME"; then
    package="$(sdkmanager --list_installed | cut -f1 -d'|' | grep system-images | tr -d ' ' | tail -n 1)"
    echo "Creating AVD $AVD_NAME using $package..."
    echo "no" | avdmanager create avd -n $AVD_NAME --package "$package" --force
fi

# If there's an emulator instance running with our AVD, shut it down first.
if [ "$(adb -s $ADB_DEVICE emu avd name | head -n1 | sed 's/[[:space:]]*$//')" = "$AVD_NAME" ]; then
    echo An emulator is already running. Going to shut it down.
    adb -s $ADB_DEVICE emu kill
fi

# Launch the emulator
echo "Launching emulator on $AVD_NAME..."
logfile=$(mktemp)

if [ "${RUNNER_ENVIRONMENT-}" = github-hosted ]; then
    # For some reason avdmanager on github runners puts newly created AVDs under
    # the following dir. So point ANDROID_AVD_HOME to it so the emulator can find
    # the AVD.
    export ANDROID_AVD_HOME=~/.config/.android/avd
fi

# Make sure that the adb server is running before starting the emulator,
# otherwise the emulator will not start correctly. Notably, the adb server may
# not be running on our self-hosted runners.
adb start-server

emulator -avd $AVD_NAME -port $PORT -no-window -gpu swiftshader_indirect \
         -no-snapshot -noaudio -no-boot-anim -no-metrics >$logfile &
EMULATOR_PID=$!

echo Emulator log file: $logfile
echo "Waiting for Android emulator to be fully booted..."

until adb -s $ADB_DEVICE shell getprop sys.boot_completed | grep -qm 1 '1'; do
  sleep 1
done

echo "Emulator started. PID: $EMULATOR_PID"

echo  "ADB_DEVICE=$ADB_DEVICE"
