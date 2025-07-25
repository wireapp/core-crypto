


# BUILD_OUTPUT='Ineligible destinations for the "InteropClient" scheme:
#     { platform:iOS, error:iOS 18.2 is not installed. To use with Xcode, first download and install the platform }'


# MISSING_VERSION=$(echo "$BUILD_OUTPUT" | \
#   grep -oE 'iOS [0-9]+\.[0-9]+ is not installed' | \
#   sed -E 's/iOS ([0-9]+\.[0-9]+) is not installed/\1/')

echo "Detecting Simulator failed. Trying to find latest Simulator version and rerun."

# Get the latest available iOS runtime version
LATEST_IOS_RUNTIME=$(xcrun simctl list runtimes | \
  grep 'iOS' | grep -v unavailable | \
  sed -E 's/.*iOS ([0-9\.]+).*/\1/' | \
  sort -Vr | head -n 1)

# Extract iPhone 16 Simulator ID for that runtime
SIMULATOR_ID=$(xcrun simctl list devices available | \
sed -n '/-- iOS 18.5 --/,/^--/p' | \
grep -E '^ *iPhone 16 \(' | \
sed -E 's/^.*\(([A-F0-9-]{36})\).*/\1/')

if [ -z "$SIM_ID" ]; then
  echo "No iPhone 16 simulator found for iOS $RUNTIME"
  exit 1
else

echo $SIMULATOR_ID
