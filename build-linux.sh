#!/bin/sh
set -eu
cd "$(dirname "$0")"

mkdir -p dist
set --
# ponytail: static musl builds by CPU; add distro packages only if needed.
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf i686-unknown-linux-musl; do
    cargo zigbuild --locked --release --target-dir target --target "$target"
    name="relay-tui-$target"
    install -m 755 "target/$target/release/relay-tui" "dist/$name"
    set -- "$@" "$name"
done
(cd dist && shasum -a 256 "$@" > SHA256SUMS)
install -m 755 install.sh dist/install.sh
