#!/usr/bin/env bash
set -e

PLUGIN_SRC="$(dirname "$0")/../src/ida_pro_mcp/mcp-plugin.py"
PLUGIN_DIR="$HOME/.idapro/plugins"

mkdir -p "$PLUGIN_DIR"

if [ "$1" = "--copy" ]; then
  cp "$PLUGIN_SRC" "$PLUGIN_DIR/mcp-plugin.py"
else
  ln -sf "$PLUGIN_SRC" "$PLUGIN_DIR/mcp-plugin.py"
fi

echo "Plugin installed to $PLUGIN_DIR/mcp-plugin.py"
