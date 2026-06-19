UV ?= uv
PYTHON ?= python3
DIST_DIR ?= dist

PACKAGE_NAME := ida-pro-mcp
WHEEL_NAME := ida_pro_mcp
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -n 1)

.DEFAULT_GOAL := package

.PHONY: help clean build package check test install version

help:
	@echo "Available targets:"
	@echo "  make package  Clean, build, validate, and generate SHA256SUMS (default)"
	@echo "  make build    Build wheel and source distribution in $(DIST_DIR)/"
	@echo "  make check    Validate generated distributions"
	@echo "  make test     Run the non-IDA unit tests"
	@echo "  make install  Install the generated wheel on this machine"
	@echo "  make clean    Remove generated build artifacts"
	@echo "  make version  Print the package version"

version:
	@echo "$(PACKAGE_NAME) $(VERSION)"

clean:
	rm -rf build "$(DIST_DIR)"
	find . -maxdepth 1 -type d -name '*.egg-info' -exec rm -rf {} +

build: clean
	$(UV) build --out-dir "$(DIST_DIR)"

check: build
	$(UV) run --with twine twine check "$(DIST_DIR)"/*

package: check
	cd "$(DIST_DIR)" && sha256sum *.whl *.tar.gz > SHA256SUMS
	@echo
	@echo "Package ready in $(DIST_DIR)/:"
	@ls -lh "$(DIST_DIR)"
	@echo
	@echo "Copy the .whl file to another machine, then run:"
	@echo "  python -m pip install --force-reinstall ./$(WHEEL_NAME)-$(VERSION)-py3-none-any.whl"
	@echo "  ida-pro-mcp --install"

test:
	$(UV) run pytest -q tests/test_idalib_supervisor.py tests/test_browser_transport_guards.py

install: package
	$(PYTHON) -m pip install --force-reinstall "$(DIST_DIR)"/*.whl
