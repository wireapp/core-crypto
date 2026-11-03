#!/usr/bin/env bash
# Run the benchmark matrix over every variant built by build-variants.sh.
#
#   cc-bench/run.sh                     # everything
#   cc-bench/run.sh 'primitive-cs1-*'   # only scenarios matching a glob
#   VARIANTS=main,aws-lc cc-bench/run.sh
#   RUNS=5 MLS_RUNS=3 cc-bench/run.sh   # quicker, noisier
#
# Results go to cc-bench/results/<scenario>.{json,md}, or to $RESULTS if set; summarize.py turns
# them into one table.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
variants="${VARIANTS:-main,graviola,aws-lc}"
runs="${RUNS:-20}"
warmup=3
filter="${1:-*}"

for variant in ${variants//,/ }; do
  [ -x "$here/bin/cc-bench-$variant" ] || { echo "missing bin/cc-bench-$variant; run build-variants.sh" >&2; exit 1; }
done
command -v hyperfine > /dev/null || { echo "hyperfine is not installed" >&2; exit 1; }

results="${RESULTS:-$here/results}"
mkdir -p "$results"

bench() {
  local name="$1"
  shift
  # shellcheck disable=SC2053 # $filter is meant as a glob
  [[ "$name" == $filter ]] || return 0
  echo "==> $name"
  hyperfine --shell=none --warmup "$warmup" --runs "$runs" --style basic \
    -L variant "$variants" \
    --command-name "{variant}" \
    --export-json "$results/$name.json" \
    --export-markdown "$results/$name.md" \
    "$here/bin/cc-bench-{variant} $*"
}

# Iteration counts put each run's measured work at roughly 0.1–1 s on main on an M-series Mac,
# well above process start-up.
for cs in 1 2 3 5 7; do
  bench "primitive-cs$cs-hash-1k" --ciphersuite $cs primitive hash --iterations 100000 --size 1024
  bench "primitive-cs$cs-aead-seal-1k" --ciphersuite $cs primitive aead-seal --iterations 50000 --size 1024
  bench "primitive-cs$cs-aead-open-1k" --ciphersuite $cs primitive aead-open --iterations 50000 --size 1024
  bench "primitive-cs$cs-aead-seal-64k" --ciphersuite $cs primitive aead-seal --iterations 1000 --size 65536
  bench "primitive-cs$cs-hkdf-extract" --ciphersuite $cs primitive hkdf-extract --iterations 50000 --size 64
  bench "primitive-cs$cs-hkdf-expand" --ciphersuite $cs primitive hkdf-expand --iterations 100000
  bench "primitive-cs$cs-sig-keygen" --ciphersuite $cs primitive sig-keygen --iterations 1000
  bench "primitive-cs$cs-sig-sign" --ciphersuite $cs primitive sig-sign --iterations 1000 --size 256
  bench "primitive-cs$cs-sig-verify" --ciphersuite $cs primitive sig-verify --iterations 1000 --size 256
  bench "primitive-cs$cs-hpke-seal" --ciphersuite $cs primitive hpke-seal --iterations 500 --size 64
  bench "primitive-cs$cs-hpke-open" --ciphersuite $cs primitive hpke-open --iterations 500 --size 64
  bench "primitive-cs$cs-hpke-derive-keypair" --ciphersuite $cs primitive hpke-derive-keypair --iterations 1000
done

# The MLS scenarios run for seconds each, so fewer runs keep the whole matrix to a few hours
# without much loss: their run-to-run variation is small relative to their length.
runs="${MLS_RUNS:-10}"
warmup=1
for cs in 1 2 7; do
  bench "mls-cs$cs-keypackages" --ciphersuite $cs mls keypackages --count 200
  for members in 10 100; do
    bench "mls-cs$cs-create-group-m$members" --ciphersuite $cs mls create-group --members $members
    bench "mls-cs$cs-messages-m$members-64b" --ciphersuite $cs mls messages --members $members --count 1000 --size 64
    bench "mls-cs$cs-messages-m$members-64k" --ciphersuite $cs mls messages --members $members --count 100 --size 65536
    bench "mls-cs$cs-commits-m$members" --ciphersuite $cs mls commits --members $members --count 100
    # Setup alone, to subtract from the scenarios above. It is the same for messages and commits.
    bench "mls-cs$cs-setup-m$members" --ciphersuite $cs --setup-only mls commits --members $members
    bench "mls-cs$cs-create-group-setup-m$members" --ciphersuite $cs --setup-only mls create-group --members $members
  done
done
