#!/usr/bin/env bash

mise reshim golangci-lint

linter="$(mise which golangci-lint)"

$linter "$@"
