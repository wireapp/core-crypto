set -euo pipefail

# The name of the Android Virtual Device we're going to use.
AVD_NAME=test-phone

# PATH updates
export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH

# Create an AVD if it does not exist
if ! avdmanager list avd | grep -q "^Name: $AVD_NAME"; then
    package="$(sdkmanager --list_installed | cut -f1 -d'|' | grep system-images | tr -d ' ' | tail -n 1)"
    echo "Creating AVD $AVD_NAME using $package..."
    echo "no" | avdmanager create avd -n $AVD_NAME --package "$package" --force
fi

# If there's an emulator instance running with our AVD, shut it down first.
if [ "$(adb emu avd name | head -n1 | sed 's/[[:space:]]*$//')" = "$AVD_NAME" ]; then
    echo An emulator is already running. Going to shut it down.
    adb emu kill
fi

# Launch the emulator
echo "Launching emulator on $AVD_NAME..."
logfile=$(mktemp)
emulator -avd $AVD_NAME -no-window -gpu swiftshader_indirect -no-snapshot -noaudio -no-boot-anim -no-metrics >$logfile &
EMULATOR_PID=$!

echo Emulator log file: $logfile
echo "Waiting for Android emulator to be fully booted..."

until adb shell getprop sys.boot_completed | grep -qm 1 '1'; do
  sleep 1
done

echo "Emulator started. PID: $EMULATOR_PID"
