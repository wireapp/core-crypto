#!/bin/sh
#
# This script is used to start test-wire-server before the test suite is run,
# because starting Keycloak requires that the redirect URL, which points to the
# test Wire server, is known.

case "$TEST_IDP" in
    authelia | keycloak)
        echo Using $TEST_IDP
        ;;

    *)
        echo "You need to set TEST_IDP variable to 'authelia' or 'keycloak'."
        exit 1
        ;;
esac

tmpfile=$(mktemp)
rm ${tmpfile}
mkfifo ${tmpfile}
cargo run --locked --bin test-wire-server > ${tmpfile} &
test_wire_server_pid=$!

# The test suite needs this environment variable in order to set up the test
# environment.
read TEST_WIRE_SERVER_ADDR < ${tmpfile}
export TEST_WIRE_SERVER_ADDR

echo -e \\nRunning nextest with arguments \"$@\"
cargo nextest run --ignore-default-filter --locked -p wire-e2e-identity "$@"
test_exit_code="$?"

# Clean up.
case "$TEST_IDP" in
    authelia)
        (docker kill authelia.local && docker rm authelia.local) > /dev/null
        ;;

    keycloak)
        (docker kill keycloak && docker rm keycloak) > /dev/null
        ;;
esac

kill ${test_wire_server_pid}
rm ${tmpfile}

exit "$test_exit_code"
