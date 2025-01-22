# Update version numbers of various core-crypto components.
new_version=$1
for crate in crypto-macros \
             crypto-ffi \
             crypto \
             interop \
             keystore-dump \
             keystore \
             mls-provider; do
    sed -i "0,/^version = \"[^\"]\+\"/{s//version = \"${new_version}\"/;b;}" $crate/Cargo.toml
done

# Make sure workspace Cargo.lock is updated with new versions.
cargo update -w

# Update the NPM package version. Be careful not to overwrite the same
# file we're reading from.
js_path=crypto-ffi/bindings/js
jq "setpath([\"version\"]; \"${new_version}\")" ${js_path}/package.json > ${js_path}/package.json.new
mv ${js_path}/package.json.new ${js_path}/package.json

# Update Maven package version.
sed -i "0,/^VERSION_NAME=[0-9.]\+$/{s//VERSION_NAME=${new_version}/;b;}" crypto-ffi/bindings/gradle.properties
