set -e
cd $(realpath $(dirname $0))

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

# PATH updates
export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$PATH

# =========================
# INSTALL REQUIRED COMPONENTS
# =========================
LATEST_BUILD_TOOLS=$(sdkmanager --list \
      | grep "build-tools;" \
      | grep -v "rc" \
      | awk -F ';' '{print $2}' \
      | awk '{print $1}' \
      | sort -V \
      | tail -n1)

echo "Installing platform-tools, build tools $LATEST_BUILD_TOOLS, emulator, platform $ANDROID_API_LEVEL, and system image ($ANDROID_ARCH)..."

yes | sdkmanager --licenses >/dev/null
sdkmanager --install "build-tools;$LATEST_BUILD_TOOLS"
sdkmanager --install "platform-tools"
sdkmanager --install "platforms;android-$ANDROID_API_LEVEL"
sdkmanager --install "emulator" --channel=0
sdkmanager --install "system-images;android-$ANDROID_API_LEVEL;default;$ANDROID_ARCH" --channel=0
