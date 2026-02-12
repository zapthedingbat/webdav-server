#!/bin/sh
# Copy default config to CONFIG_PATH only if it does not exist (never overwrite).
CONFIG_PATH="${CONFIG_PATH:-/config/config.yaml}"
DEFAULT_CONFIG=/app/config.default.yaml
if [ ! -f "$CONFIG_PATH" ] && [ -f "$DEFAULT_CONFIG" ]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  cp "$DEFAULT_CONFIG" "$CONFIG_PATH"
fi

# Copy default index page to INDEX_HTML_PATH only if it does not exist (never overwrite).
INDEX_HTML_PATH="${INDEX_HTML_PATH:-/config/index.html}"
DEFAULT_INDEX_HTML=/app/index.default.html
if [ ! -f "$INDEX_HTML_PATH" ] && [ -f "$DEFAULT_INDEX_HTML" ]; then
  mkdir -p "$(dirname "$INDEX_HTML_PATH")"
  cp "$DEFAULT_INDEX_HTML" "$INDEX_HTML_PATH"
fi

exec "$@"
