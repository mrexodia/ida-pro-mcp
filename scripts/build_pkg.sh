#!/usr/bin/env bash
set -e

ROOT_DIR="$(dirname "$0")/.."
DIST_DIR="$ROOT_DIR/dist"
PKG_DIR="$DIST_DIR/pkg"
WHEEL_DIR="$DIST_DIR/wheels"
DMG_NAME="ida-pro-mcp.dmg"

rm -rf "$DIST_DIR"
mkdir -p "$PKG_DIR" "$WHEEL_DIR"

cd "$ROOT_DIR"
uv build

# Build llama-cpp-python wheels for both macOS architectures
export CMAKE_ARGS="-DLLAMA_METAL=on"
export FORCE_CMAKE=1
ARCHFLAGS="-arch x86_64" uv pip wheel --wheel-dir "$WHEEL_DIR" --no-binary llama_cpp_python llama-cpp-python
ARCHFLAGS="-arch arm64" uv pip wheel --wheel-dir "$WHEEL_DIR" --no-binary llama_cpp_python llama-cpp-python

cp -r src offline_llm ida-plugin.json README.md "$PKG_DIR/"
cp dist/*.whl "$PKG_DIR/" 2>/dev/null || true
cp "$WHEEL_DIR"/*.whl "$PKG_DIR/" 2>/dev/null || true

hdiutil create "$DIST_DIR/$DMG_NAME" -volname "IDA Pro MCP" -srcfolder "$PKG_DIR" -ov -format UDZO

echo "DMG created at $DIST_DIR/$DMG_NAME"

