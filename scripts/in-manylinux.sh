#!/usr/bin/env bash
# Runs a command in a manylinux_2_28 container (AlmaLinux 8, glibc 2.28), with this repository and
# the host's Rust toolchain mounted. Anything built this way needs glibc 2.28 at most, so it loads on
# RHEL 8, SLES 15 SP3, Debian 11, Ubuntu 20.04 and newer. Used by make/jvm.mk; needs a Linux host with
# Docker and the same architecture.
#
#   scripts/in-manylinux.sh <x86_64|aarch64> <command> [args...]
#
# The images are pinned by digest (tag 2026.09.05-1). To update them, pick a newer tag of
# quay.io/pypa/manylinux_2_28_x86_64 and quay.io/pypa/manylinux_2_28_aarch64 and replace both digests.
set -euo pipefail

arch="$1"
shift
case "$arch" in
  x86_64)
    platform=linux/amd64
    image=quay.io/pypa/manylinux_2_28_x86_64@sha256:53390351aeb4688114b02c36a23b3e6ce1166ee9b7afc5df1a4f776354fc764c
    ;;
  aarch64)
    platform=linux/arm64
    image=quay.io/pypa/manylinux_2_28_aarch64@sha256:ad74e53b713f3b07d8c889c526dc0c6500da9827b45e38739570875fef52e28f
    ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != "$arch" ]; then
  echo "scripts/in-manylinux.sh $arch needs a Linux $arch host, not $(uname -s) $(uname -m)" >&2
  exit 1
fi
if ! command -v docker >/dev/null; then
  echo "scripts/in-manylinux.sh needs Docker" >&2
  exit 1
fi

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
repo="$(pwd)"
volumes=(--volume "$repo:$repo" --volume "$cargo_home:$cargo_home" --volume "$rustup_home:$rustup_home")

# Build scripts call git. In a linked worktree, the git directory lies outside the repository.
git_dir="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
if [ -n "$git_dir" ] && [ "${git_dir#"$repo"/}" = "$git_dir" ]; then
  volumes+=(--volume "$git_dir:$git_dir")
fi

# The container keeps the image's PATH, which has the compiler toolchain, and puts cargo in front.
exec docker run --rm --platform "$platform" \
  --user "$(id -u):$(id -g)" --env HOME=/tmp \
  "${volumes[@]}" --workdir "$repo" \
  --env CARGO_HOME="$cargo_home" --env RUSTUP_HOME="$rustup_home" \
  --env RUSTFLAGS --env RUSTUP_TOOLCHAIN --env CARGO_NET_GIT_FETCH_WITH_CLI --env CARGO_TERM_COLOR \
  "$image" bash -c 'export PATH="$CARGO_HOME/bin:$PATH"; exec "$@"' bash "$@"
