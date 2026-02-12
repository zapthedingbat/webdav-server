#!/bin/sh
# Copy default config to CONFIG_PATH only if it does not exist (never overwrite).
CONFIG_PATH="${CONFIG_PATH:-/config/config.yaml}"
DEFAULT_CONFIG=/app/config.default.yaml
if [ ! -f "$CONFIG_PATH" ] && [ -f "$DEFAULT_CONFIG" ]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  cp "$DEFAULT_CONFIG" "$CONFIG_PATH"
fi

exec "$@"
