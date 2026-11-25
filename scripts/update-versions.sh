# Update version numbers of various core-crypto components.
new_version=$1
# The crate versions are inherited from the workspace manifest.
perl -0777 -pi -e \
    's/^version = "[^"]+"/version = "'"$new_version"'"/m' \
    Cargo.toml

# Make sure workspace Cargo.lock is updated with new versions.
cargo update -w

# Update the NPM package versions, and the copies recorded in bun.lock.
js=crypto-ffi/bindings/js
for pkg in browser native; do
  (cd "$js/packages/$pkg" && bun pm version "$new_version" --no-git-tag-version)
done
(cd "$js" && bun update --lockfile-only @wireapp/core-crypto @wireapp/core-crypto-native)

# Update Maven package version.
perl -pi -e 's/^VERSION_NAME=[0-9A-Za-z._-]+/VERSION_NAME='"$new_version"'/' crypto-ffi/bindings/gradle.properties

# Update Swift package version.
perl -pi -e 's/^MARKETING_VERSION=[0-9A-Za-z._-]+/MARKETING_VERSION='"$new_version"'/' crypto-ffi/bindings/swift/BuildSettings.xcconfig

# Both dylib version settings use the numeric project version.
swift_project_version=${new_version%%-*}
perl -pi -e 's/^CURRENT_PROJECT_VERSION=[0-9A-Za-z._-]+/CURRENT_PROJECT_VERSION='"$swift_project_version"'/' crypto-ffi/bindings/swift/BuildSettings.xcconfig
