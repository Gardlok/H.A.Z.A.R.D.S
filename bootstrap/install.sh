#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(dirname "$SCRIPT_DIR")

PREFIX=${PREFIX:-"$HOME/.local"}
HOST_KIND=desktop
PERSISTENCE=local
ROLE=development
DRY_RUN=0

usage() {
    printf '%s\n' \
        "Usage: install.sh [OPTIONS]" \
        "" \
        "Install HAZARDS from this source checkout." \
        "" \
        "Options:" \
        "  --prefix PATH             Installation prefix (default: ~/.local)" \
        "  --host KIND               desktop, laptop, or remote" \
        "  --persistence MODE        local, roaming, or ghost" \
        "  --role ROLE               development, operations, or research" \
        "  --dry-run                 Print the plan without changing files" \
        "  -h, --help                Show this help"
}

require_value() {
    if [ "$#" -lt 2 ]; then
        printf 'install.sh: %s requires a value\n' "$1" >&2
        exit 2
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            require_value "$@"
            PREFIX=$2
            shift 2
            ;;
        --host)
            require_value "$@"
            HOST_KIND=$2
            shift 2
            ;;
        --persistence)
            require_value "$@"
            PERSISTENCE=$2
            shift 2
            ;;
        --role)
            require_value "$@"
            ROLE=$2
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'install.sh: unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$HOST_KIND" in
    desktop|laptop|remote) ;;
    *)
        printf 'install.sh: invalid host: %s\n' "$HOST_KIND" >&2
        exit 2
        ;;
esac

case "$PERSISTENCE" in
    local|roaming|ghost) ;;
    *)
        printf 'install.sh: invalid persistence mode: %s\n' "$PERSISTENCE" >&2
        exit 2
        ;;
esac

case "$ROLE" in
    development|operations|research) ;;
    *)
        printf 'install.sh: invalid role: %s\n' "$ROLE" >&2
        exit 2
        ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
    printf '%s\n' \
        "install.sh: cargo is required for source installation." \
        "A verified prebuilt-release bootstrap will be added during release engineering." >&2
    exit 1
fi

printf '%s\n' \
    "HAZARDS source installation" \
    "  prefix:      $PREFIX" \
    "  host:        $HOST_KIND" \
    "  persistence: $PERSISTENCE" \
    "  role:        $ROLE"

if [ "$DRY_RUN" -eq 1 ]; then
    printf '%s\n' \
        "" \
        "dry run: cargo install --locked --path crates/hazards-cli --root $PREFIX"
    exit 0
fi

cargo install \
    --locked \
    --force \
    --path "$REPOSITORY_ROOT/crates/hazards-cli" \
    --root "$PREFIX"

"$PREFIX/bin/hazards" profile resolve \
    --host "$HOST_KIND" \
    --persistence "$PERSISTENCE" \
    --role "$ROLE"

printf '%s\n' \
    "" \
    "Installed $PREFIX/bin/hazards" \
    "Ensure $PREFIX/bin is on PATH, then run: hazards doctor"
