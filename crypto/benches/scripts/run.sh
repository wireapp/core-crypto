# Runs all benches in quick mode to prototype faster
cargo bench --bench commit --bench encryption --bench key_package --bench public_group_state --bench create_group -- --quick
