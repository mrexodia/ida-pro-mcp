#!/usr/bin/env bash
set -e

ROOT_DIR="$(dirname "$0")/.."
DIST_DIR="$ROOT_DIR/dist"
PKG_DIR="$DIST_DIR/pkg"
DMG_NAME="ida-pro-mcp.dmg"

rm -rf "$DIST_DIR"
mkdir -p "$PKG_DIR"

cd "$ROOT_DIR"
uv build

cp -r src ida-plugin.json README.md "$PKG_DIR/"
cp dist/*.whl "$PKG_DIR/" 2>/dev/null || true

hdiutil create "$DIST_DIR/$DMG_NAME" -volname "IDA Pro MCP" -srcfolder "$PKG_DIR" -ov -format UDZO

echo "DMG created at $DIST_DIR/$DMG_NAME"

