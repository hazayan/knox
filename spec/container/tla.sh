#!/usr/bin/env bash

export CLASSPATH="/tools/tla2tools.jar:${CLASSPATH}"

: ${TLC_WORKERS:=2}

java  -XX:+UseParallelGC tlc2.TLC -workers ${TLC_WORKERS} -deadlock -cleanup "$@"
