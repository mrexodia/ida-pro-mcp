#!/bin/bash
uv run ida-pro-mcp --generate-docs
rm -rf dist
uv build
uv publish