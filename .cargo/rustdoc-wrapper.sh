#!/bin/sh
# The README file in repo root contains some github-flavored Markdown constructs
# that are not understood by rustdoc. Remove them so rustdoc doesn't complain.
if [ "$CARGO_CRATE_NAME" = "core_crypto" ]; then
    tempfile=$(mktemp)
    # we do not want to expand the contained backticks as expressions here;
    # they are code fences
    #shellcheck disable=SC2016
    sed -E \
        -e '/\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]/d' \
        -e 's/```ignore/```text/g' \
        "$CARGO_MANIFEST_DIR/../README.md" > "$tempfile"
    export STRIPPED_README_PATH="$tempfile"
fi
rustdoc "$@"
