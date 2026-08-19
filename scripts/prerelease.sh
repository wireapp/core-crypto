#!/usr/bin/env bash

# Determine whether or not we need to create a new release branch

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "usage: $0 <MAJOR_VERSION>"
    exit 1
fi
major_version="$1"

if ! rg '^\d+$' <<< "$major_version" > /dev/null; then
    echo "usage: $0 <MAJOR_VERSION>"
    echo "MAJOR_VERSION must be a bare number"
    exit 1
fi

remote_refs="$(git ls-remote origin)"

if ! rg 'refs/tags/v(\d+)\.\d+\.\d+$' --replace '$1' -o <<< "$remote_refs" | rg -x "$major_version" > /dev/null; then
    echo "no tag exists for this major version; base your release on main"
    exit
fi

if rg "refs/heads/release/$major_version\.x$" <<< "$remote_refs" > /dev/null; then
    echo "release branch 'release/$major_version.x' exists"
    echo "cherry-pick the appropriate PRs onto that release branch,"
    echo "then release from there"
    exit
fi

major_tag_re="$(printf 'refs/tags/(v%d\.\d+\.\d+)$' "$major_version")"
major_tag="$(
    rg -o "$major_tag_re" --replace '$1' <<< "$remote_refs" |
    sort -r --version-sort |
    head -n 1
)"

echo "Last tag for this major version: $major_tag"
echo
echo "Inspect these PRs. Do **all** of them want to go into this release?"
echo "- If yes, then release based on main."
echo "- If no, then create a new release branch on the previous tag and cherry-pick onto it:"
echo "    git checkout -b release/$major_version.x tags/$major_tag"
echo
major_tag_timestamp="$(git log -1 --format=%cI "$major_tag^{commit}")"
gh pr list --base main --state merged --search "merged:>$major_tag_timestamp"
