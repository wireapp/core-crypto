#!/usr/bin/env bash
# Build cc-bench against several core-crypto revisions.
#
#   cc-bench/build-variants.sh main=main graviola=simon/spike/graviola-on-main aws-lc=<rev>
#
# Each variant gets a detached worktree (default: ../cc-bench-wt/<name> next to the repo). This
# crate is copied into it as `.cc-bench`, so `../crypto` resolves to that revision's library,
# along with the revision's own Cargo.lock, so every dependency they share is at the version the
# revision pins. The binary lands in cc-bench/bin/cc-bench-<name>, the resolved commit next to it.
#
# Environment variables for one variant's build follow its revision, separated by commas:
#
#   cc-bench/build-variants.sh aws-lc-big=<rev>,AWS_LC_SYS_SMALL=0
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
worktrees="${CC_BENCH_WORKTREES:-$repo/../cc-bench-wt}"

if [ $# -eq 0 ]; then
  echo "usage: $0 <name>=<rev> ..." >&2
  exit 1
fi

mkdir -p "$here/bin" "$worktrees"

for spec in "$@"; do
  name="${spec%%=*}"
  rev_and_env="${spec#*=}"
  rev="${rev_and_env%%,*}"
  build_env=()
  if [ "$rev_and_env" != "$rev" ]; then
    IFS=, read -r -a build_env <<< "${rev_and_env#*,}"
  fi
  sha="$(git -C "$repo" rev-parse --verify "$rev^{commit}")"
  wt="$worktrees/$name"

  echo "==> $name: $rev ($sha)${build_env[*]:+ with ${build_env[*]}}"
  if [ -d "$wt" ]; then
    git -C "$wt" checkout --quiet --detach "$sha"
  else
    git -C "$repo" worktree add --quiet --detach "$wt" "$sha"
  fi

  rsync -a --delete --exclude target --exclude bin --exclude results --exclude Cargo.lock \
    "$here/" "$wt/.cc-bench/"
  cp "$wt/Cargo.lock" "$wt/.cc-bench/Cargo.lock"

  (cd "$wt/.cc-bench" && env ${build_env[@]+"${build_env[@]}"} cargo build --release --quiet)
  cp "$wt/.cc-bench/target/release/cc-bench" "$here/bin/cc-bench-$name"
  echo "$sha${build_env[*]:+ ${build_env[*]}}" > "$here/bin/cc-bench-$name.rev"
done
