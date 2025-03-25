set -e

echo "Running cargo clean..."
cargo clean

echo "Deleting all node_modules directories..."
find . -type d -name "node_modules" -exec rm -rf {} +

echo "Done."
