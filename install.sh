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

{ : </dev/tty; } 2>/dev/null || fail 'Для запуска relay-tui нужен интерактивный терминал.'
as_root=()
if (( EUID != 0 )); then
    command -v sudo >/dev/null || fail 'sudo не установлен. Запусти установщик от root.'
    sudo -v </dev/tty || fail 'Не удалось получить права через sudo. Запусти установщик от root.'
    as_root=(sudo --)
fi
bin_dir=/usr/local/bin
bin="$bin_dir/relay-tui"
"${as_root[@]}" mkdir -p -- "$bin_dir" || fail "Не удалось подготовить $bin_dir с правами root."
if [[ -e $bin || -L $bin ]]; then
    [[ -f $bin && ! -L $bin ]] || fail "$bin не является обычным файлом. Установка отменена."
fi

base=https://github.com/oshinono/vps-relay-setup/releases/latest/download
name="relay-tui-$target"
tmp=$(mktemp -d)
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
    "${as_root[@]}" sh -c '
        set -eu
        staged=$(mktemp "$1.XXXXXXXX")
        trap '\''rm -f -- "$staged"'\'' EXIT
        install -m 755 -- "$2" "$staged"
        printf "%s  %s\n" "$3" "$staged" | sha256sum --status -c -
        mv -fT -- "$staged" "$1"
    ' sh "$bin" "$tmp/$name" "$hash" || fail "Не удалось установить $bin с правами root."
    printf 'Установлен %s (%s)\n' "$bin" "$arch"
fi
[[ -x $bin ]] || fail "$bin не исполняемый. Выполни: chmod +x '$bin'"
"${as_root[@]}" "$bin" </dev/tty || fail 'Не удалось запустить relay-tui с правами root. См. ошибку выше.'
