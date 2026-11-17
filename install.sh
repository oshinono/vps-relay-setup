#!/usr/bin/env bash
set -euo pipefail

fail() { printf '%s\n' "$*" >&2; exit 1; }

[[ $(uname -s) == Linux ]] || fail 'Поддерживается только Linux.'
arch=$(uname -m)
case "$arch" in
    x86_64|aarch64) target="$arch-unknown-linux-musl" ;;
    armv7l) target=armv7-unknown-linux-musleabihf ;;
    i686) target=i686-unknown-linux-musl ;;
    *) fail "Неподдерживаемая архитектура: $arch" ;;
esac

base=https://github.com/oshinono/vps-relay-setup/releases/latest/download
name="relay-tui-$target"
tmp=$(mktemp -d ./.relay-tui.XXXXXXXX)
trap 'rm -rf -- "$tmp"' EXIT

fetch() { curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 120 "$base/$1" -o "$tmp/$1"; }
fetch SHA256SUMS
hash=$(awk -v name="$name" '$2 == name {print $1}' "$tmp/SHA256SUMS")
[[ $hash =~ ^[[:xdigit:]]{64}$ ]] || fail "Нет корректной суммы SHA-256 для $name"
fetch "$name"
printf '%s  %s\n' "$hash" "$name" | (cd "$tmp" && sha256sum -c -)
chmod 755 "$tmp/$name"
ln -T -- "$tmp/$name" ./relay-tui || fail 'Не удалось создать ./relay-tui. Проверь права и не занят ли путь.'
printf 'Скачан ./relay-tui (%s)\n' "$arch"
