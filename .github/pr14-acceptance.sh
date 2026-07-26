#!/usr/bin/env bash
set -euo pipefail

if [[ "${HAZARDS_ACCEPT_PHASE:-root}" == "root" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    build-essential \
    binutils \
    bubblewrap \
    ca-certificates \
    cmake \
    curl \
    jq \
    pkg-config \
    python3 \
    libfontconfig1-dev \
    libfreetype6-dev \
    libxkbcommon-dev \
    libxcb-xfixes0-dev

  uid="${WORKSPACE_UID:?WORKSPACE_UID is required}"
  gid="${WORKSPACE_GID:?WORKSPACE_GID is required}"
  if group_entry="$(getent group "$gid")"; then
    group_name="${group_entry%%:*}"
  else
    group_name=hazards-accept
    groupadd --gid "$gid" "$group_name"
  fi
  if user_entry="$(getent passwd "$uid")"; then
    user_name="${user_entry%%:*}"
    user_home="$(printf '%s' "$user_entry" | cut -d: -f6)"
  else
    user_name=hazards-accept
    user_home=/home/hazards-accept
    useradd --create-home --uid "$uid" --gid "$group_name" "$user_name"
  fi
  mkdir -p "$user_home"
  chown "$uid:$gid" "$user_home"

  exec runuser -u "$user_name" -- env \
    HAZARDS_ACCEPT_PHASE=builder \
    HOME="$user_home" \
    USER="$user_name" \
    LOGNAME="$user_name" \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    bash /workspace/.github/pr14-acceptance.sh
fi

cd /workspace
rm -rf acceptance
mkdir -p acceptance

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
  sh -s -- -y --profile minimal --default-toolchain 1.97.1
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
rustc +1.97.1 -vV > acceptance/rustc.txt
cargo +1.97.1 -Vv > acceptance/cargo.txt
bwrap --version > acceptance/bwrap.txt
cargo +1.97.1 build --locked -p hazards-cli --bins

REAL_RUSTUP_HOME="$HOME/.rustup"
REAL_CARGO_HOME="$HOME/.cargo"
ACCEPT_ROOT="$(mktemp -d)"
export HOME="$ACCEPT_ROOT/home"
export XDG_CONFIG_HOME="$ACCEPT_ROOT/config"
export XDG_CACHE_HOME="$ACCEPT_ROOT/cache"
export XDG_STATE_HOME="$ACCEPT_ROOT/state"
export RUSTUP_HOME="$REAL_RUSTUP_HOME"
export CARGO_HOME="$REAL_CARGO_HOME"
mkdir -p "$HOME"
printf '%s\n' "$ACCEPT_ROOT" > acceptance/accept-root.txt

HAZARDS_BIN=/workspace/target/debug/hazards
PREPARE_BIN=/workspace/target/debug/hazards-source-prepare
DEPENDENCY_BIN=/workspace/target/debug/hazards-cargo-dependencies
CONTRACT_BIN=/workspace/target/debug/hazards-build-contract
BUILD_BIN=/workspace/target/debug/hazards-source-build
PINNED_BIN="$(rustc +1.97.1 --print sysroot)/bin"
SYSTEM_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

"$HAZARDS_BIN" provision acquire \
  --tool alacritty \
  --host desktop \
  --persistence local \
  --role development

"$PREPARE_BIN" \
  --tool alacritty \
  --host desktop \
  --persistence local \
  --role development \
  --json > acceptance/source-preparation.json
jq -e 'length == 1 and .[0].receipt.outcome == "prepared"' \
  acceptance/source-preparation.json

"$DEPENDENCY_BIN" \
  --tool alacritty \
  --host desktop \
  --persistence local \
  --role development \
  --json > acceptance/dependencies.json
jq -e '
  length == 1 and
  .[0].receipt.dependency_count == 291 and
  (.[] .receipt.downloaded_count + .[] .receipt.cache_hit_count) == 291
' acceptance/dependencies.json

SOURCE_RECEIPTS_BEFORE="$(find "$XDG_STATE_HOME/hazards/receipts/source-preparations" -type f | wc -l)"
DEPENDENCY_RECEIPTS_BEFORE="$(find "$XDG_STATE_HOME/hazards/receipts/cargo-dependencies" -type f | wc -l)"

contract_environment=(
  HOME="$HOME"
  XDG_CONFIG_HOME="$XDG_CONFIG_HOME"
  XDG_CACHE_HOME="$XDG_CACHE_HOME"
  XDG_STATE_HOME="$XDG_STATE_HOME"
  PATH="$PINNED_BIN:$SYSTEM_PATH"
)

env -i "${contract_environment[@]}" \
  "$CONTRACT_BIN" \
    --tool alacritty \
    --host desktop \
    --persistence local \
    --role development \
    --json > acceptance/contract.json

jq -e '
  .read_only == true and
  .execution_enabled == false and
  (.items | length) == 1 and
  .items[0].status == "contract_ready" and
  (.items[0].contract_sha256 | test("^[0-9a-f]{64}$")) and
  .items[0].dependencies.dependency_count == 291 and
  .items[0].toolchain.rustc_release == "1.97.1" and
  .items[0].toolchain.cargo_release == "1.97.1" and
  ([.items[0].native_commands[].satisfied] | all) and
  ([.items[0].pkg_config[].satisfied] | all) and
  .items[0].environment.satisfied == true and
  .items[0].invocation.network_enabled == false and
  (.items[0].invocation.program | endswith("/bwrap"))
' acceptance/contract.json

CONTRACT_DIGEST="$(jq -r '.items[0].contract_sha256' acceptance/contract.json)"
printf '%s\n' "$CONTRACT_DIGEST" > acceptance/contract-digest.txt

set +e
env -i "${contract_environment[@]}" \
  "$BUILD_BIN" \
    --tool alacritty \
    --host desktop \
    --persistence local \
    --role development \
    --confirm "sha256:$CONTRACT_DIGEST" \
    --json > acceptance/build-result.json 2> acceptance/build-command.stderr
BUILD_STATUS=$?
set -e
printf '%s\n' "$BUILD_STATUS" > acceptance/build-exit-status.txt

if [[ -s acceptance/build-result.json ]]; then
  RECEIPT_PATH="$(jq -r '.receipt_path // empty' acceptance/build-result.json)"
  ARTIFACT_PATH="$(jq -r '.receipt.artifact.object_path // empty' acceptance/build-result.json)"
  STDOUT_PATH="$(jq -r '.receipt.stdout_log_path // empty' acceptance/build-result.json)"
  STDERR_PATH="$(jq -r '.receipt.stderr_log_path // empty' acceptance/build-result.json)"
  [[ -n "$RECEIPT_PATH" && -f "$RECEIPT_PATH" ]] && cp "$RECEIPT_PATH" acceptance/source-build-receipt.json
  [[ -n "$STDOUT_PATH" && -f "$STDOUT_PATH" ]] && cp "$STDOUT_PATH" acceptance/stdout.log
  [[ -n "$STDERR_PATH" && -f "$STDERR_PATH" ]] && cp "$STDERR_PATH" acceptance/stderr.log
  [[ -n "$ARTIFACT_PATH" && -f "$ARTIFACT_PATH" ]] && \
    stat --printf='%n %s %a\n' "$ARTIFACT_PATH" > acceptance/artifact-stat.txt
fi

test "$BUILD_STATUS" -eq 0
jq -e '
  .receipt.outcome == "succeeded" and
  .receipt.contract_sha256 == $digest and
  .receipt.build_root_preserved == false and
  .receipt.exit_code == 0 and
  .receipt.signal == null and
  .receipt.artifact.name == "alacritty" and
  .receipt.artifact.target == "x86_64-unknown-linux-gnu" and
  .receipt.artifact.elf_machine == 62 and
  (.receipt.artifact.sha256 | test("^[0-9a-f]{64}$"))
' --arg digest "$CONTRACT_DIGEST" acceptance/build-result.json

RECEIPT_PATH="$(jq -r '.receipt_path' acceptance/build-result.json)"
ARTIFACT_PATH="$(jq -r '.receipt.artifact.object_path' acceptance/build-result.json)"
ARTIFACT_SHA="$(jq -r '.receipt.artifact.sha256' acceptance/build-result.json)"
STDOUT_PATH="$(jq -r '.receipt.stdout_log_path' acceptance/build-result.json)"
STDERR_PATH="$(jq -r '.receipt.stderr_log_path' acceptance/build-result.json)"
BUILD_ROOT="$(dirname "$(jq -r '.receipt.invocation.current_dir' acceptance/build-result.json)")"

test -f "$RECEIPT_PATH"
test -f "$ARTIFACT_PATH"
test -x "$ARTIFACT_PATH"
test -f "$STDOUT_PATH"
test -f "$STDERR_PATH"
test ! -e "$BUILD_ROOT"
test ! -e "$HOME/.local/bin/alacritty"
test "$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')" = "$ARTIFACT_SHA"
test "$(find "$XDG_STATE_HOME/hazards/receipts/source-preparations" -type f | wc -l)" = "$SOURCE_RECEIPTS_BEFORE"
test "$(find "$XDG_STATE_HOME/hazards/receipts/cargo-dependencies" -type f | wc -l)" = "$DEPENDENCY_RECEIPTS_BEFORE"
