#!/usr/bin/env bash

set -e
set -x

mypy sandbox_cli --explicit-package-bases
ruff check --fix sandbox_cli
ruff format sandbox_cli
