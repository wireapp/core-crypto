# Keystore dump

Since keystore data is encrypted at rest, for dev purposes only we might need to dump it to introspect it and understand
the issue we are trying to troubleshoot better. This command serves exactly that purpose: given the encryption key and
the path to the database file this will export its content to json. It does not work for WASM