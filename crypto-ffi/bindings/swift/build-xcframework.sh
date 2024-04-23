#!/bin/sh

set -e

xcodebuild archive \
    -project 'WireCoreCrypto/WireCoreCrypto.xcodeproj' \
    -scheme 'WireCoreCrypto' \
    -configuration Release \
    -archivePath 'WireCoreCrypto-ios.xcarchive' \
    -destination 'generic/platform=ios' \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES

xcodebuild archive \
    -project 'WireCoreCrypto/WireCoreCrypto.xcodeproj' \
    -scheme 'WireCoreCrypto' \
    -configuration Release \
    -archivePath 'WireCoreCrypto-simulator.xcarchive' \
    -destination 'generic/platform=ios Simulator' \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES

xcodebuild -create-xcframework \
    -archive 'WireCoreCrypto-ios.xcarchive' \
    -framework 'WireCoreCrypto.framework' \
    -archive 'WireCoreCrypto-simulator.xcarchive' \
    -framework 'WireCoreCrypto.framework' \
    -output 'WireCoreCrypto.xcframework'

zip -r WireCoreCrypto.xcframework.zip WireCoreCrypto.xcframework

rm -rf WireCoreCrypto.xcframework
rm -rf WireCoreCrypto-ios.xcarchive
rm -rf WireCoreCrypto-simulator.xcarchive
