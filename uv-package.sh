#!/bin/bash
uv run ida-pro-mcp --generate-docs
uv build
uv publish

