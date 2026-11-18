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

if (( EUID == 0 )); then
    bin_dir=/usr/local/bin
else
    bin_dir="${HOME:?HOME не задан}/.local/bin"
fi
bin="$bin_dir/relay-tui"
mkdir -p -- "$bin_dir"
if [[ -e $bin || -L $bin ]]; then
    [[ -f $bin && ! -L $bin ]] || fail "$bin не является обычным файлом. Установка отменена."
fi

base=https://github.com/oshinono/vps-relay-setup/releases/latest/download
name="relay-tui-$target"
tmp=$(mktemp -d "$bin_dir/.relay-tui.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT

fetch() { curl -q -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time "$2" "$base/$1" -o "$tmp/$1"; }
fetch SHA256SUMS 15
hash=$(awk -v name="$name" '$2 == name {print $1}' "$tmp/SHA256SUMS")
[[ $hash =~ ^[[:xdigit:]]{64}$ ]] || fail "Нет корректной суммы SHA-256 для $name"
if [[ -f $bin ]] && (cd "$bin_dir" && printf '%s  relay-tui\n' "$hash" | sha256sum --status -c -); then
    printf 'Актуальная версия: %s\n' "$bin"
else
    fetch "$name" 120
    printf '%s  %s\n' "$hash" "$name" | (cd "$tmp" && sha256sum -c -)
    chmod 755 "$tmp/$name"
    mv -fT -- "$tmp/$name" "$bin"
    printf 'Установлен %s (%s)\n' "$bin" "$arch"
fi
[[ -x $bin ]] || fail "$bin не исполняемый. Выполни: chmod +x '$bin'"
"$bin" </dev/tty
