#!/bin/sh
set -eu

case "$(uname -m)" in
  x86_64 | amd64) SB_ARCH=amd64 ;;
  aarch64 | arm64) SB_ARCH=arm64 ;;
  *)
    echo "Неподдерживаемая архитектура: $(uname -m)" >&2
    exit 1
    ;;
esac

SB_VERSION="${SINGBOX_VERSION:-1.14.4}"
APP_DIR="${APP_DIR:-/app}"
DATA_DIR="${DATA_DIR:-/data}"
SB_BIN="$DATA_DIR/bin/sing-box"
SB_MARK="$DATA_DIR/bin/version"

if [ ! -x "$SB_BIN" ] || [ "$(cat "$SB_MARK" 2>/dev/null || true)" != "$SB_VERSION" ]; then
  echo "[start] скачиваю sing-box ${SB_VERSION} (${SB_ARCH})"
  mkdir -p "$DATA_DIR/bin" /tmp/sing-box-dl
  URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/sing-box-${SB_VERSION}-linux-${SB_ARCH}-musl.tar.gz"
  if ! wget -qO /tmp/sing-box.tar.gz "$URL"; then
    echo "[start] не удалось скачать sing-box: $URL" >&2
    exit 1
  fi
  tar -xzf /tmp/sing-box.tar.gz -C /tmp/sing-box-dl --strip-components=1
  mv /tmp/sing-box-dl/sing-box "$SB_BIN"
  chmod 0755 "$SB_BIN"
  echo "$SB_VERSION" > "$SB_MARK"
  rm -rf /tmp/sing-box-dl /tmp/sing-box.tar.gz
  echo "[start] sing-box установлен: $("$SB_BIN" version | head -1)"
fi

export PATH="$DATA_DIR/bin:$PATH"
exec node "$APP_DIR/server.js"
