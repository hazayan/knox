# TLA+ Quick Start for Knox

## 5-Minute Setup

```bash
# 1. Install Java (if not already installed)
java -version  # Should be 11+

# 2. Download TLC model checker
wget https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
     -O /usr/local/lib/tla2tools.jar

# 3. Run all checks
cd formal-verification/tla
make check-all
```

Expected output:
```
========================================
Checking KeyVersionStateMachine...
========================================
Model checking completed. No error has been found.
...
2847361 states generated, 543210 distinct states found

========================================
Checking MasterKeyRotation...
========================================
Model checking completed. No error has been found.
...

========================================
Checking DistributedLocking...
========================================
Model checking completed. No error has been found.
...

========================================
All model checks completed successfully!
========================================
```

## What Gets Verified

### ✅ Key Version State Machine
- **Invariant**: Exactly one Primary version at all times
- **Invariant**: Version hash stays consistent
- **Property**: Only valid state transitions occur
- **Time**: ~30 seconds

### ✅ Master Key Rotation
- **Invariant**: No decryption failures during rotation
- **Invariant**: Old cryptors removed only when safe
- **Property**: Crash-safe re-encryption
- **Time**: ~60 seconds

### ✅ Distributed Locking
- **Invariant**: Mutual exclusion (only one lock holder)
- **Invariant**: No lost updates
- **Property**: Deadlock-free
- **Time**: ~90 seconds

## Common Commands

```bash
# Check specific component
make check-version    # Just the version state machine
make check-rotation   # Just the rotation protocol
make check-locking    # Just the distributed locks

# Clean up generated files
make clean

# Verify TLC installation
make test-install

# Run with more workers (faster on multi-core)
make check-all TLC_WORKERS=8
```

## Understanding Failures

If you see:
```
Error: Invariant SinglePrimaryInvariant is violated.
```

This means TLC found a sequence of operations that breaks the invariant. The trace will show exactly how:

```
State 1: versions = {[id=v1, status=Primary]}
State 2: [AddVersion(v2)] versions = {[id=v1, status=Primary], [id=v2, status=Active]}
State 3: [PromoteToPrimary(v2)] versions = {[id=v1, status=Active], [id=v2, status=Primary]}
```

Read the trace from top to bottom to understand the bug.

## When to Run Checks

- ✅ Before committing changes to key management logic
- ✅ When adding new version state transitions
- ✅ When modifying rotation protocol
- ✅ When changing etcd locking behavior
- ✅ In CI/CD pipeline (recommended)

## Next Steps

For deeper understanding, read:
- `README.md` - Full documentation
- Individual `.tla` files - Commented specifications
- TLA+ Tutorial: https://learntla.com/

## Help

If checks fail unexpectedly:
1. Ensure Java 11+ is installed
2. Verify TLC jar is at correct path: `make test-install`
3. Check for recent code changes that might have broken invariants
4. Read the error trace carefully - it shows the exact bug scenario

If you need to modify the specs:
1. Edit the `.tla` file
2. Optionally edit the `.cfg` file (constants, invariants to check)
3. Run `make check-<component>`
4. Fix any violations found
5. Update code to match verified spec

---

**Pro Tip**: Keep this window open while developing Knox features. Run `make check-all` before every commit. It's faster than debugging production issues! 🚀
