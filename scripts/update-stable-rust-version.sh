#!/usr/bin/env bash
# Usage: ./update-rust-version.sh 1.90

set -euo pipefail

NEW_VERSION="$1"

if [[ -z "$NEW_VERSION" ]]; then
    echo "Usage: $0 <rust-version>"
    exit 1
fi

# Find all Cargo.toml files
fd --type f --glob 'Cargo.toml' --exclude .cargo | while read -r TOML_FILE; do
    echo "Updating $TOML_FILE"
    # Cross-platform in-place replacement using Perl
    perl -pi -e "s/^\s*rust-version\s*=.*/rust-version = \"$NEW_VERSION\"/" "$TOML_FILE"
done

echo "All Cargo.toml files updated to rust-version = $NEW_VERSION"
