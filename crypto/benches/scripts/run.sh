# Runs all benches in quick mode to prototype faster
cargo bench --bench commit --bench encryption --bench key_package --bench create_group --bench mls_proteus -- --quick
