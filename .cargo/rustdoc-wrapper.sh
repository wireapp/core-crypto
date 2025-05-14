#!/bin/sh
# The README file in repo root contains some github-flavored Markdown constructs
# that are not understood by rustdoc. Remove them so rustdoc doesn't complain.
if [ $CARGO_CRATE_NAME = "core_crypto" ]; then
    tempfile=$(mktemp)
    sed -E \
        -e '/\[!(note|warning|important)\]/d' \
        -e 's/```ignore/```text/g' \
        $CARGO_MANIFEST_DIR/../README.md > $tempfile
    export STRIPPED_README_PATH=$tempfile
fi
rustdoc "$@"
