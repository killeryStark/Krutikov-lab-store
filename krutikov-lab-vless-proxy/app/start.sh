#!/bin/sh
set -eu

case "$(uname -m)" in
  x86_64 | amd64) XRAY_ARCH=64 ;;
  aarch64 | arm64) XRAY_ARCH=arm64-v8a ;;
  *)
    echo "Неподдерживаемая архитектура: $(uname -m)" >&2
    exit 1
    ;;
esac

XRAY_VERSION="${XRAY_VERSION:-26.10.21}"
APP_DIR="${APP_DIR:-/app}"
DATA_DIR="${DATA_DIR:-/data}"
XRAY_BIN="$DATA_DIR/bin/xray"
XRAY_MARK="$DATA_DIR/bin/version"

if [ ! -x "$XRAY_BIN" ] || [ "$(cat "$XRAY_MARK" 2>/dev/null || true)" != "xray-$XRAY_VERSION" ]; then
  echo "[start] скачиваю Xray-core ${XRAY_VERSION} (${XRAY_ARCH})"
  mkdir -p "$DATA_DIR/bin"
  URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip"
  if ! wget -qO /tmp/xray.zip "$URL"; then
    echo "[start] не удалось скачать Xray: $URL" >&2
    exit 1
  fi
  node "$APP_DIR/extract.js" /tmp/xray.zip "$XRAY_BIN" xray
  chmod 0755 "$XRAY_BIN"
  printf 'xray-%s' "$XRAY_VERSION" > "$XRAY_MARK"
  rm -f /tmp/xray.zip
  rm -f "$DATA_DIR/bin/sing-box" "$DATA_DIR/sing-box.json"
  echo "[start] Xray установлен: $("$XRAY_BIN" version | head -1)"
fi

export PATH="$DATA_DIR/bin:$PATH"
exec node "$APP_DIR/server.js"
