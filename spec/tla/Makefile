# Makefile for running TLA+ model checking on Knox specifications
#
# Prerequisites:
#   - TLA+ Toolbox or standalone TLC (https://github.com/tlaplus/tlaplus)
#   - Java 11+ (required by TLC)
#
# Usage:
#   make check-all          - Run all model checks
#   make check-version      - Check KeyVersionStateMachine
#   make check-rotation     - Check MasterKeyRotation
#   make check-locking      - Check DistributedLocking
#   make clean              - Remove generated files

# TLC configuration
TLC_JAR ?= /usr/local/lib/tla2tools.jar
JAVA ?= java
TLC_WORKERS ?= 4
TLC_FLAGS ?= -workers $(TLC_WORKERS) -deadlock -cleanup

# If TLC_JAR doesn't exist, try to download it
$(TLC_JAR):
	@echo "TLC not found at $(TLC_JAR)"
	@echo "Download from: https://github.com/tlaplus/tlaplus/releases/latest"
	@echo "Or set TLC_JAR=/path/to/tla2tools.jar"
	@exit 1

.PHONY: all check-all check-version check-rotation check-locking clean help

all: check-all

help:
	@echo "Knox TLA+ Model Checking"
	@echo ""
	@echo "Targets:"
	@echo "  check-all       - Run all model checks"
	@echo "  check-version   - Check Key Version State Machine"
	@echo "  check-rotation  - Check Master Key Rotation Protocol"
	@echo "  check-locking   - Check Distributed Locking"
	@echo "  clean           - Remove generated files"
	@echo ""
	@echo "Environment Variables:"
	@echo "  TLC_JAR        - Path to tla2tools.jar (default: /usr/local/lib/tla2tools.jar)"
	@echo "  TLC_WORKERS    - Number of worker threads (default: 4)"

check-all: check-version check-rotation check-locking
	@echo ""
	@echo "========================================"
	@echo "All model checks completed successfully!"
	@echo "========================================"

check-version: $(TLC_JAR)
	@echo "========================================"
	@echo "Checking KeyVersionStateMachine..."
	@echo "========================================"
	$(JAVA) -XX:+UseParallelGC -cp $(TLC_JAR) tlc2.TLC \
		$(TLC_FLAGS) \
		-config KeyVersionStateMachine.cfg \
		KeyVersionStateMachine.tla
	@echo ""

check-rotation: $(TLC_JAR)
	@echo "========================================"
	@echo "Checking MasterKeyRotation..."
	@echo "========================================"
	$(JAVA) -XX:+UseParallelGC -cp $(TLC_JAR) tlc2.TLC \
		$(TLC_FLAGS) \
		-config MasterKeyRotation.cfg \
		MasterKeyRotation.tla
	@echo ""

check-locking: $(TLC_JAR)
	@echo "========================================"
	@echo "Checking DistributedLocking..."
	@echo "========================================"
	$(JAVA) -XX:+UseParallelGC -cp $(TLC_JAR) tlc2.TLC \
		$(TLC_FLAGS) \
		-config DistributedLocking.cfg \
		DistributedLocking.tla
	@echo ""

# Experimental: Check with smaller state space for quick validation
check-quick: $(TLC_JAR)
	@echo "Quick validation (reduced state space)..."
	$(JAVA) -XX:+UseParallelGC -cp $(TLC_JAR) tlc2.TLC \
		-workers 2 -depth 10 -deadlock \
		-config KeyVersionStateMachine.cfg \
		KeyVersionStateMachine.tla

clean:
	rm -rf states/
	rm -f *.dot *.out *.st
	rm -f MC.tla MC.cfg

# Generate state graph visualization (requires GraphViz)
visualize-version: $(TLC_JAR)
	$(JAVA) -cp $(TLC_JAR) tlc2.TLC \
		-dump dot,colorize,actionlabels version_graph.dot \
		-config KeyVersionStateMachine.cfg \
		KeyVersionStateMachine.tla
	dot -Tpdf version_graph.dot -o version_graph.pdf
	@echo "Graph saved to version_graph.pdf"

.PHONY: test-install
test-install:
	@echo "Testing TLA+ toolchain installation..."
	@echo "Java version:"
	@$(JAVA) -version
	@echo ""
	@if [ -f "$(TLC_JAR)" ]; then \
		echo "TLC found at: $(TLC_JAR)"; \
		$(JAVA) -cp $(TLC_JAR) tlc2.TLC -h | head -n 5; \
	else \
		echo "ERROR: TLC not found at $(TLC_JAR)"; \
		exit 1; \
	fi
