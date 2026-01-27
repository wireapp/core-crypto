# Update version numbers of various core-crypto components.
new_version=$1
for crate in crypto-macros \
             crypto-ffi \
             crypto \
             interop \
             keystore-dump \
             keystore; do

        perl -0777 -pi -e \
            's/^version = "[^"]+"/version = "'"$new_version"'"/m' \
            "$crate/Cargo.toml"
    done

# Make sure workspace Cargo.lock is updated with new versions.
cargo update -w

# Update the NPM package version. Be careful not to overwrite the same
# file we're reading from.
js_path=crypto-ffi/bindings/js
jq "setpath([\"version\"]; \"${new_version}\")" ${js_path}/package.json > ${js_path}/package.json.new
mv ${js_path}/package.json.new ${js_path}/package.json

# Update Maven package version.
perl -pi -e 's/^VERSION_NAME=[0-9.]+/VERSION_NAME='"$new_version"'/' crypto-ffi/bindings/gradle.properties

# Update Swift package version.
perl -pi -e 's/^MARKETING_VERSION=[0-9.]+/MARKETING_VERSION='"$new_version"'/' crypto-ffi/bindings/swift/BuildSettings.xcconfig
perl -pi -e 's/^CURRENT_PROJECT_VERSION=[0-9.]+/CURRENT_PROJECT_VERSION='"$new_version"'/' crypto-ffi/bindings/swift/BuildSettings.xcconfig
