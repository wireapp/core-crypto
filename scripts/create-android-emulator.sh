set -e

# =========================
# SET ANDROID ARCH BASED ON OS
# =========================
OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
    ANDROID_ARCH="arm64-v8a"
elif [ "$OS" = "Linux" ]; then
    ANDROID_ARCH="x86_64"
else
    echo "Unsupported OS: $OS"
    exit 1
fi

echo "Using Android architecture: $ANDROID_ARCH"

# =========================
# CONFIGURATION
# =========================
ANDROID_API_LEVEL=32
ANDROID_AVD=test_api_$ANDROID_API_LEVEL

# Android SDK root - if command line tools installed via Homebrew, set
# ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/$NDK_VERSION
export ANDROID_AVD_HOME=$HOME/.config/.android/avd

# PATH updates
export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH

# =========================
# CREATE AVD
# =========================
# Delete existing AVD if it exists
if avdmanager list avd | grep -q "^  Name: $ANDROID_AVD$"; then
    echo "Deleting existing AVD $ANDROID_AVD..."
    avdmanager delete avd -n $ANDROID_AVD
fi

# Create new AVD
echo "Creating AVD $ANDROID_AVD..."
mkdir -p "$ANDROID_AVD_HOME"
echo "no" | avdmanager create avd \
    -n $ANDROID_AVD \
    --package "system-images;android-$ANDROID_API_LEVEL;default;$ANDROID_ARCH" \
    --force \
    -p "$ANDROID_AVD_HOME/$ANDROID_AVD"

# =========================
# LAUNCH EMULATOR HEADLESS
# =========================
echo "Launching emulator $ANDROID_AVD headlessly..."
emulator -avd $ANDROID_AVD -no-window -gpu swiftshader_indirect -no-snapshot -noaudio -no-boot-anim -no-metrics >/dev/null &
EMULATOR_PID=$!

echo "Waiting for Android emulator to be fully booted..."

until adb shell getprop sys.boot_completed | grep -m 1 '1'; do
  sleep 1
done

until adb shell pm list packages >/dev/null 2>&1; do
  sleep 1
done

echo "Emulator started. PID: $EMULATOR_PID"

echo $EMULATOR_PID
