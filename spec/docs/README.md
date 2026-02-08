# Knox Formal Verification

This directory contains formal specifications and verification for Knox's core functionality using TLA+ (Temporal Logic of Actions).

## Overview

Knox is a production secret key management and rotation system. Formal verification helps us prove critical safety and liveness properties that are difficult to test exhaustively with traditional testing approaches.

We've formalized three core aspects of Knox:

1. **Key Version State Machine** - The version lifecycle and rotation logic
2. **Master Key Rotation Protocol** - Graceful cryptor rotation with zero downtime
3. **Distributed Locking** - Multi-node coordination via etcd

## Why TLA+ for Knox?

Secret management systems have unique requirements:

- **Safety-critical**: A bug could leak secrets or cause data loss
- **Concurrency**: Multiple nodes accessing shared state
- **State machines**: Complex version transitions
- **Rare edge cases**: Rotation + crash + concurrent access scenarios are hard to test

TLA+ allows us to:

- **Prove** invariants hold in ALL possible executions
- **Explore** billions of states automatically
- **Find** subtle bugs that evade testing (e.g., race conditions, deadlocks)
- **Document** the intended behavior precisely

## Directory Structure

```
formal-verification/
├── README.md                          # This file
├── tla/                               # TLA+ specifications
│   ├── KeyVersionStateMachine.tla     # Phase 1: Version state machine
│   ├── KeyVersionStateMachine.cfg     # Model checking configuration
│   ├── MasterKeyRotation.tla          # Phase 2: Cryptor rotation
│   ├── MasterKeyRotation.cfg          # Model checking configuration
│   ├── DistributedLocking.tla         # Phase 3: etcd coordination
│   ├── DistributedLocking.cfg         # Model checking configuration
│   └── Makefile                       # Automated model checking
└── results/                           # Model checking results (generated)
```

## Installation

### Prerequisites

1. **Java 11 or later**
   ```bash
   java -version
   ```

2. **TLA+ Tools** (TLC model checker)

   Download the latest `tla2tools.jar` from:
   https://github.com/tlaplus/tlaplus/releases/latest

   ```bash
   # Example installation to /usr/local/lib/
   sudo mkdir -p /usr/local/lib
   sudo wget https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
        -O /usr/local/lib/tla2tools.jar
   ```

3. **Optional: TLA+ Toolbox** (IDE with visual debugger)
   
   Download from: https://github.com/tlaplus/tlaplus/releases/latest
   
   The Toolbox provides:
   - Syntax highlighting
   - Interactive model checking
   - State graph visualization
   - Error trace exploration

### Verify Installation

```bash
cd formal-verification/tla
make test-install
```

Should output Java version and TLC version.

## Running Model Checks

### Quick Start

Run all model checks:

```bash
cd formal-verification/tla
make check-all
```

This will verify all three specifications, taking 2-5 minutes on a modern machine.

### Individual Specifications

Check specific components:

```bash
# Phase 1: Key Version State Machine
make check-version

# Phase 2: Master Key Rotation
make check-rotation

# Phase 3: Distributed Locking
make check-locking
```

### Understanding Output

Successful check:
```
Model checking completed. No error has been found.
  Estimates of the probability that TLC did not check all reachable states
  because two distinct states had the same fingerprint:
  calculated (optimistic):  val = 1.2E-12
...
2847361 states generated, 543210 distinct states found, 0 states left on queue.
```

Key metrics:
- **States generated**: Total states explored
- **Distinct states**: Unique states (after deduplication)
- **0 states left**: Complete exploration (all paths checked)

If an invariant violation is found:
```
Error: Invariant SinglePrimaryInvariant is violated.
The behavior up to this point is:
State 1: ...
State 2: ...
State 3: <violation>
```

TLC will show the exact sequence of steps leading to the violation.

## What We're Verifying

### Phase 1: Key Version State Machine

**File**: `KeyVersionStateMachine.tla`

**Corresponds to**: `pkg/types/knox.go` - `KeyVersionList`

**Invariants Checked**:
1. `SinglePrimaryInvariant` - Exactly one Primary version exists at all times
2. `UniqueVersionIDs` - Version IDs are unique within a key
3. `VersionHashConsistency` - Version hash matches computed hash
4. `NonEmptyVersionList` - At least one version always exists

**State Transitions Modeled**:
- `AddVersion(vid)` - Add new version as Active
- `PromoteToPrimary(vid)` - Active → Primary (demotes old Primary → Active)
- `DemoteToInactive(vid)` - Active → Inactive
- `RestoreToActive(vid)` - Inactive → Active

**Invalid Transitions Proven Unreachable**:
- Primary → Inactive (without promoting another)
- Inactive → Primary (must go through Active)

**Model Size**: ~50,000 states (tractable, fast)

### Phase 2: Master Key Rotation Protocol

**File**: `MasterKeyRotation.tla`

**Corresponds to**: `pkg/crypto/rotation.go` - `KeyRotationManager`

**Critical Property**: `NoDecryptionFailures`
- Every key in the database can ALWAYS be decrypted
- Even during rotation, crashes, or concurrent operations

**Invariants Checked**:
1. `NoDecryptionFailures` - All keys decryptable with available cryptors
2. `CurrentNotInOld` - Current cryptor never in old cryptors list
3. `UniqueOldCryptors` - No duplicates in fallback chain
4. `ReencryptedConsistency` - Re-encryption tracking is accurate

**Operations Modeled**:
- `WriteNewKey(kid)` - Encrypt new data (uses current cryptor)
- `ReadKey(kid)` - Decrypt data (tries current, then old cryptors)
- `RotateMasterKey(new)` - Promote new cryptor, demote current to old
- `StartReencrypt(kid)` - Begin re-encrypting a key
- `CompleteReencrypt(kid)` - Finish re-encrypting (atomic)
- `CrashDuringReencrypt` - Model crash-safety
- `RemoveOldCryptor` - Cleanup after re-encryption

**Key Scenarios Verified**:
- Rotation with no re-encryption: Old keys still readable
- Concurrent reads during rotation: No failures
- Crash during re-encryption: Can resume, no corruption
- Premature old cryptor removal: Prevented (would cause decryption failures)

**Model Size**: ~500,000 states

### Phase 3: Distributed Locking

**File**: `DistributedLocking.tla`

**Corresponds to**: `pkg/storage/etcd/etcd.go` - distributed locks

**Critical Property**: `MutualExclusion`
- At most one node holds a lock on any key at any time
- Prevents concurrent modifications and data races

**Invariants Checked**:
1. `MutualExclusion` - Only one lock holder per key
2. `LockSessionValidity` - Held locks have active sessions
3. `WaitingNodesValid` - Waiting nodes have active sessions
4. `VersionMonotonicity` - Optimistic concurrency versions increase
5. `NoLostUpdates` - Compare-and-swap prevents conflicts

**Operations Modeled**:
- `CreateSession(node)` - Establish etcd session with TTL
- `AcquireLock(node, key)` - Obtain distributed lock
- `ReleaseLock(node, key)` - Release lock
- `UpdateKey(node, key, value, expectedVersion)` - Atomic update with CAS
- `SessionExpires(node)` - Session timeout (releases all locks)
- `AdvanceTime` - Model passage of time

**Key Scenarios Verified**:
- Two nodes try to lock same key: Only one succeeds
- Session expires: Locks automatically released
- Network partition (modeled via session timeout): No split-brain
- Optimistic concurrency conflict: Update fails, data not corrupted
- Deadlock: Proven impossible with current design

**Model Size**: ~1,000,000 states

## Interpreting Results

### All Checks Pass ✅

This means TLC exhaustively verified that:
- All invariants hold in every reachable state
- All safety properties are satisfied
- No deadlocks exist
- The state space is fully explored

This is a **strong guarantee** - not just "we didn't find bugs in our test cases", but "we proved bugs of these types are impossible in the design".

### Invariant Violation ❌

If TLC finds a violation, it provides:

1. **Error trace**: Sequence of states leading to the violation
2. **Variable values**: Complete state at each step
3. **Action taken**: Which operation caused each transition

Example debugging workflow:

```
Error: Invariant NoDecryptionFailures is violated.

State 1: currentCryptor = c1, oldCryptors = <<>>, database = {[id=k1, encryptedWith=c1]}
State 2: [RotateMasterKey(c2)] currentCryptor = c2, oldCryptors = <<c1>>, database = {[id=k1, encryptedWith=c1]}
State 3: [RemoveOldCryptor] currentCryptor = c2, oldCryptors = <<>>, database = {[id=k1, encryptedWith=c1]}
State 4: [ReadKey(k1)] <VIOLATION: Cannot decrypt k1 - encrypted with c1 but only c2 available>
```

This trace shows the bug: We removed c1 from oldCryptors before re-encrypting k1.

Fix: Add precondition to `RemoveOldCryptor` that all keys must be re-encrypted first.

### Performance Tuning

If model checking is too slow:

1. **Reduce constants** in `.cfg` file:
   ```
   MaxKeys = 2  (instead of 3)
   MaxVersions = 3  (instead of 4)
   ```

2. **Add state constraints**:
   ```tla
   CONSTRAINT Cardinality(database) <= 2
   ```

3. **Increase workers**:
   ```bash
   make check-all TLC_WORKERS=8
   ```

4. **Use symmetry** (advanced):
   Add to `.cfg`:
   ```
   SYMMETRY SymmetrySet
   ```

## Connecting Specs to Code

### Key Version State Machine → Code

| TLA+ Action | Knox Code |
|-------------|-----------|
| `AddVersion(vid)` | `POST /v0/keys/{keyID}/versions/` → `server/routes.go:postVersionHandler` |
| `PromoteToPrimary(vid)` | `PUT /v0/keys/{keyID}/versions/{vid}/` with `status=Primary` → `pkg/types/knox.go:KeyVersionList.Update()` |
| `DemoteToInactive(vid)` | `PUT /v0/keys/{keyID}/versions/{vid}/` with `status=Inactive` |
| `SinglePrimaryInvariant` | `pkg/types/knox.go:KeyVersionList.Validate()` line 234 |

### Master Key Rotation → Code

| TLA+ Action | Knox Code |
|-------------|-----------|
| `RotateMasterKey(new)` | `pkg/crypto/rotation.go:KeyRotationManager.RotateTo()` line 67 |
| `CompleteReencrypt(kid)` | `pkg/crypto/rotation.go:ReencryptDB()` line 105 |
| `RemoveOldCryptor` | `pkg/crypto/rotation.go:KeyRotationManager.RemoveOldCryptor()` line 89 |
| `NoDecryptionFailures` | Invariant enforced by rotation logic |

### Distributed Locking → Code

| TLA+ Action | Knox Code |
|-------------|-----------|
| `AcquireLock(node, key)` | `pkg/storage/etcd/etcd.go:lockKey()` line 234 |
| `UpdateKey(node, key, ...)` | `pkg/storage/etcd/etcd.go:UpdateKey()` line 156 with transaction |
| `SessionExpires(node)` | etcd session TTL handling, automatic lock release |
| `MutualExclusion` | Guaranteed by `concurrency.NewMutex()` in etcd client |

## Extending the Specifications

### Adding New Properties

To verify additional invariants:

1. Define the property in TLA+:
   ```tla
   MyNewInvariant == \A k \in KeyIDs: SomeCondition(k)
   ```

2. Add to `.cfg` file:
   ```
   INVARIANTS
       MyNewInvariant
   ```

3. Run model checker:
   ```bash
   make check-version
   ```

### Modeling New Features

When adding features to Knox:

1. **Update the spec** to include new operations
2. **Add invariants** that must hold
3. **Run TLC** to verify before implementing in Go
4. **Implement** with confidence that the design is sound

Example: Adding key archival:

```tla
\* New action
ArchiveVersion(vid) ==
    /\ FindVersion(vid).status = Inactive
    /\ versions' = versions \ {FindVersion(vid)}
    /\ ...
    
\* New invariant
PrimaryNeverArchived ==
    \A v \in versions: v.status = Primary => v \in versions'
```

## Continuous Integration

To add model checking to CI/CD:

```yaml
# .github/workflows/formal-verification.yml
name: Formal Verification

on: [push, pull_request]

jobs:
  model-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-java@v3
        with:
          java-version: '11'
      - name: Download TLC
        run: |
          wget https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
               -O /tmp/tla2tools.jar
      - name: Run model checks
        run: |
          cd formal-verification/tla
          make check-all TLC_JAR=/tmp/tla2tools.jar
```

This ensures every commit is formally verified.

## Resources

### Learning TLA+

- **Official Tutorial**: https://learntla.com/
- **Video Course**: Leslie Lamport's TLA+ video lectures
- **Book**: "Specifying Systems" by Leslie Lamport (free PDF)
- **Examples**: https://github.com/tlaplus/Examples

### TLA+ for Distributed Systems

- **AWS Uses TLA+**: https://lamport.azurewebsites.net/tla/amazon.html
- **Azure Cosmos DB**: Formal verification case study
- **Raft Consensus**: TLA+ specification

### Knox-Specific Context

- `pkg/types/knox.go` - Core types and validation
- `pkg/crypto/rotation.go` - Rotation manager
- `pkg/storage/etcd/etcd.go` - Distributed backend

## FAQ

**Q: Does TLA+ verify the Go implementation?**

A: No, TLA+ verifies the *design* and *algorithm*. The Go code must still be tested to ensure it correctly implements the verified design. However, if the implementation closely follows the spec, and the spec is verified, we have high confidence in correctness.

**Q: Why not use Go's race detector instead?**

A: The race detector finds data races in actual executions, but only tests paths that are exercised. TLA+ explores *all* possible interleavings, finding rare race conditions that testing might miss.

**Q: How do I know the TLA+ spec matches the code?**

A: Compare carefully:
1. Read the code alongside the spec
2. Ensure TLA+ actions mirror Go functions
3. Keep specs updated when code changes
4. Consider it living documentation

**Q: Can TLC handle infinite state spaces?**

A: No, TLC is a model checker (bounded). We use finite sets (MaxKeys=3, etc.) to make checking tractable. This still finds most bugs - if a race exists, it usually appears in small models.

**Q: What about liveness properties?**

A: TLA+ can verify liveness (e.g., "rotation eventually completes"). We've included some liveness properties but focus primarily on safety (invariants) since those are critical for secret management.

## Contributing

When modifying Knox's core logic:

1. **Update TLA+ specs** to reflect design changes
2. **Run model checks** to verify new properties
3. **Document** new invariants in code comments
4. **Reference specs** in PR descriptions

Formal verification is most valuable when kept in sync with the implementation.

## Acknowledgments

TLA+ was created by Leslie Lamport (Turing Award recipient). The Knox formal verification effort is inspired by successful applications at Amazon, Microsoft, and other companies managing critical distributed systems.

---

**Last Updated**: 2025-10-24  
**Maintainer**: Knox Team  
**License**: Same as Knox project
