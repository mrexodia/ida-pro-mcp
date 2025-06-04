#!/usr/bin/env bash
set -e

if ! command -v python3.11 >/dev/null; then
  echo "Python 3.11 is required" >&2
  exit 1
fi

VENV_DIR="$(dirname "$0")/../.venv"
python3.11 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip setuptools wheel

# Compile llama-cpp-python with Metal support
export CMAKE_ARGS="-DLLAMA_METAL=on"
export FORCE_CMAKE=1
python -m pip install --no-binary llama_cpp_python llama-cpp-python

# Install project in editable mode
pip install -e "$(dirname "$0")/.."

MODEL_PATH="$1"
SETTINGS_DIR="$HOME/Library/Application Support/ida-offline-mcp"
mkdir -p "$SETTINGS_DIR"
SETTINGS_FILE="$SETTINGS_DIR/settings.json"

if [ -n "$MODEL_PATH" ]; then
  echo "{\"model_path\": \"$MODEL_PATH\"}" > "$SETTINGS_FILE"
else
  echo "{}" > "$SETTINGS_FILE"
fi

echo "Wrote settings to $SETTINGS_FILE"

