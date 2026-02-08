# Formal Properties Verified for Knox

This document lists all safety and liveness properties formally verified using TLA+, mapped to their security and correctness implications.

## Key Version State Machine Properties

### Safety Properties

#### `SinglePrimaryInvariant`
- **Formal**: `Cardinality(PrimaryVersions) = 1`
- **English**: Exactly one version is marked as Primary at all times
- **Security Impact**: Prevents ambiguity about which key to use for encryption
- **Code Reference**: `pkg/types/knox.go:234` - `KeyVersionList.Validate()`
- **Violation Impact**: Could encrypt with wrong version, or fail to encrypt

#### `UniqueVersionIDs`
- **Formal**: `Cardinality(versions) = Cardinality(VersionIDSet)`
- **English**: All version IDs within a key are unique
- **Security Impact**: Prevents confusion between different key versions
- **Code Reference**: `pkg/types/knox.go` - version ID generation
- **Violation Impact**: Could decrypt with wrong key, cryptographic failure

#### `VersionHashConsistency`
- **Formal**: `versionHash = ComputeVersionHash`
- **English**: Stored version hash matches computed hash of active versions
- **Security Impact**: Integrity check prevents tampering with version list
- **Code Reference**: `pkg/types/knox.go:HasVersion()` - hash verification
- **Violation Impact**: Attacker could add/remove versions without detection

#### `NonEmptyVersionList`
- **Formal**: `versions # {}`
- **English**: A key always has at least one version (the Primary)
- **Security Impact**: Ensures keys are always usable
- **Code Reference**: `server/key_manager.go:NewKey()`
- **Violation Impact**: Key becomes unusable, data loss

### State Transition Properties

#### Valid Transitions
```
Active → Primary:    Allowed (via PromoteToPrimary)
Active → Inactive:   Allowed (via DemoteToInactive)
Inactive → Active:   Allowed (via RestoreToActive)
```

#### Invalid Transitions (Proven Unreachable)
```
Primary → Inactive:  Blocked (must promote another Active first)
Primary → Active:    Blocked (semantically invalid)
Inactive → Primary:  Blocked (must activate first)
```

**Security Impact**: Prevents accidental key version mismanagement that could break decryption.

---

## Master Key Rotation Properties

### Critical Safety Properties

#### `NoDecryptionFailures`
- **Formal**: `∀ k ∈ database: CanDecrypt(k)`
- **English**: Every key in the database can be decrypted with available cryptors
- **Security Impact**: Guarantees zero data loss during master key rotation
- **Code Reference**: `pkg/crypto/rotation.go:Decrypt()` - fallback chain
- **Violation Impact**: CRITICAL - Permanent data loss, secrets become unrecoverable

#### `CurrentNotInOld`
- **Formal**: `currentCryptor ∉ {oldCryptors[i]: i ∈ DOMAIN oldCryptors}`
- **English**: The current cryptor never appears in the old cryptors list
- **Security Impact**: Prevents cryptographic confusion
- **Code Reference**: `pkg/crypto/rotation.go:RotateTo()` - promotion logic
- **Violation Impact**: Ambiguous which cryptor to use, potential infinite loops

#### `UniqueOldCryptors`
- **Formal**: `∀ i,j ∈ DOMAIN oldCryptors: i≠j ⇒ oldCryptors[i]≠oldCryptors[j]`
- **English**: Old cryptors list contains no duplicates
- **Security Impact**: Efficient fallback chain, no redundant decryption attempts
- **Code Reference**: `pkg/crypto/rotation.go` - oldCryptors management
- **Violation Impact**: Performance degradation, confusing audit logs

#### `ReencryptedConsistency`
- **Formal**: `∀ kid ∈ reencrypted: ∃ k ∈ database: k.id=kid ∧ k.encryptedWith=currentCryptor`
- **English**: Keys marked as re-encrypted are actually encrypted with current cryptor
- **Security Impact**: Accurate tracking of re-encryption progress
- **Code Reference**: `pkg/crypto/rotation.go:ReencryptDB()` - progress tracking
- **Violation Impact**: Premature old cryptor removal, data loss

### Operational Properties

#### `NewWritesUseCurrentCryptor`
- **Formal**: `[][WriteNewKey(kid) ⇒ newKey.encryptedWith = currentCryptor]_vars`
- **English**: All new encryption uses the latest cryptor
- **Security Impact**: Ensures new secrets use strongest available cryptography
- **Code Reference**: `pkg/crypto/rotation.go:Encrypt()`
- **Violation Impact**: New secrets encrypted with deprecated keys

#### `SafeRemoval`
- **Formal**: `[][RemoveOldCryptor ⇒ ∀ k: k.encryptedWith ≠ oldestCryptor]_vars`
- **English**: Old cryptors only removed when no keys use them
- **Security Impact**: Prevents premature cleanup causing data loss
- **Code Reference**: `pkg/crypto/rotation.go:RemoveOldCryptor()`
- **Violation Impact**: CRITICAL - Keys become undecryptable

### Crash Safety Properties

#### `CrashSafety`
- **Formal**: `[]((reencrypting # {}) ⇒ <>Invariants)`
- **English**: System can crash during re-encryption and recover without violating invariants
- **Security Impact**: Re-encryption is resumable, no corruption on crash
- **Code Reference**: `pkg/crypto/rotation.go:ReencryptDB()` - context cancellation
- **Violation Impact**: Crash during rotation could corrupt database

---

## Distributed Locking Properties

### Mutual Exclusion (Most Critical)

#### `MutualExclusion`
- **Formal**: `∀ k ∈ KeyIDs: LockIsHeld(k) ⇒ |{n : NodeHoldsLock(n,k)}| ≤ 1`
- **English**: At most one node holds a lock on any key at any time
- **Security Impact**: Prevents concurrent modifications that could corrupt data or leak secrets
- **Code Reference**: `pkg/storage/etcd/etcd.go:lockKey()` - `concurrency.NewMutex()`
- **Violation Impact**: CRITICAL - Race conditions, data corruption, potential secret leakage

#### `LockSessionValidity`
- **Formal**: `∀ k: LockIsHeld(k) ⇒ HasActiveSession(locks[k].holder)`
- **English**: Held locks always have active etcd sessions
- **Security Impact**: Ensures locks are released when nodes fail
- **Code Reference**: `pkg/storage/etcd/etcd.go` - session management with TTL
- **Violation Impact**: Deadlocks, zombie locks after node failure

#### `WaitingNodesValid`
- **Formal**: `∀ <<n,k>> ∈ nodeWaiting: HasActiveSession(n)`
- **English**: Nodes waiting for locks have active sessions
- **Security Impact**: Only healthy nodes can acquire locks
- **Code Reference**: Session renewal in etcd client
- **Violation Impact**: Failed nodes block lock acquisition

### Consistency Properties

#### `VersionMonotonicity`
- **Formal**: `∀ k ∈ KeyIDs: etcdKeys[k].exists ⇒ etcdKeys[k].version ≥ 0`
- **English**: Key versions monotonically increase
- **Security Impact**: Optimistic concurrency control works correctly
- **Code Reference**: `pkg/storage/etcd/etcd.go:UpdateKey()` - etcd transactions
- **Violation Impact**: Lost updates, concurrent modification corruption

#### `NoLostUpdates`
- **Formal**: `[][¬∃ n1,n2,k: n1≠n2 ∧ NodeHoldsLock(n1,k) ∧ NodeHoldsLock(n2,k)]_vars`
- **English**: Two different nodes never hold the same lock simultaneously
- **Security Impact**: Prevents race conditions in key updates
- **Code Reference**: etcd's distributed lock implementation
- **Violation Impact**: CRITICAL - Conflicting updates, data races

### Liveness Properties

#### `EventualLockAcquisition`
- **Formal**: `WF_vars(AcquireLock(n,k)) ⇒ (<<n,k>> ∈ nodeWaiting ~> NodeHoldsLock(n,k))`
- **English**: If a node waits for a lock, it eventually acquires it (assuming lock becomes available)
- **Security Impact**: System doesn't deadlock
- **Code Reference**: Lock queuing in etcd
- **Violation Impact**: Deadlock, system hangs

#### `SessionExpiryReleasesLocks`
- **Formal**: `∀ n: []((HasActiveSession(n) ∧ LocksHeldBy(n)≠{}) ⇒ <>(¬HasActiveSession(n) ⇒ LocksHeldBy(n)={}))`
- **English**: When a session expires, all locks held by that node are released
- **Security Impact**: Failed nodes don't permanently hold locks
- **Code Reference**: etcd session lease mechanism
- **Violation Impact**: Permanent deadlocks after node failures

#### `NoDeadlock`
- **Formal**: `[](nodeWaiting≠{} ⇒ ∃ n,k: CanAcquireLock(n,k))`
- **English**: If nodes are waiting, at least one can make progress
- **Security Impact**: System remains available
- **Code Reference**: Lock acquisition logic
- **Violation Impact**: Total system freeze

---

## Property Hierarchy

### Priority 1: Data Loss Prevention
1. `NoDecryptionFailures` - Master key rotation
2. `SafeRemoval` - Master key rotation
3. `CrashSafety` - Master key rotation

**Why**: Permanent data loss is unacceptable in a secret management system.

### Priority 2: Consistency & Integrity
1. `MutualExclusion` - Distributed locking
2. `NoLostUpdates` - Distributed locking
3. `VersionHashConsistency` - Version state machine
4. `SinglePrimaryInvariant` - Version state machine

**Why**: Corruption or ambiguity in key data could leak secrets.

### Priority 3: Availability
1. `NoDeadlock` - Distributed locking
2. `EventualLockAcquisition` - Distributed locking
3. `SessionExpiryReleasesLocks` - Distributed locking

**Why**: System must remain operational even during failures.

---

## Threat Model Coverage

### What TLA+ Proves Knox Prevents

✅ **Race Conditions**: Distributed locking mutual exclusion prevents concurrent key modifications  
✅ **Data Loss**: Master key rotation never makes keys undecryptable  
✅ **Corruption**: Version hash integrity prevents tampering  
✅ **Deadlocks**: Liveness properties ensure progress  
✅ **Lost Updates**: Optimistic concurrency detects conflicts  
✅ **Crash Corruption**: Re-encryption is crash-safe and resumable  
✅ **Split-Brain**: Session expiry prevents zombie locks  

### What TLA+ Does NOT Cover

❌ **Implementation Bugs**: Specs verify design, not Go code (use tests + race detector)  
❌ **Cryptographic Strength**: AES-256-GCM correctness is assumed (use FIPS-validated libraries)  
❌ **Side Channels**: Timing attacks, cache attacks (use constant-time crypto primitives)  
❌ **Network Security**: TLS security (use strong cipher suites, certificate validation)  
❌ **Access Control Logic**: ACL evaluation correctness (use property-based testing)  

---

## Maintenance Guidelines

### When Code Changes Require Spec Updates

Update TLA+ specifications when modifying:

1. **Version state transitions** (`pkg/types/knox.go`)
   - Adding new statuses
   - Changing transition rules
   - Modifying version hash algorithm

2. **Master key rotation** (`pkg/crypto/rotation.go`)
   - Changing cryptor lifecycle
   - Modifying re-encryption logic
   - Adding new cryptor types

3. **Distributed coordination** (`pkg/storage/etcd/etcd.go`)
   - Changing lock acquisition logic
   - Modifying session management
   - Adding new transaction patterns

### Continuous Verification Checklist

Before merging PRs that touch core logic:

- [ ] Update TLA+ specs to reflect changes
- [ ] Run `make check-all` locally
- [ ] Verify CI passes formal verification
- [ ] Document new invariants in code comments
- [ ] Update this PROPERTIES.md if new properties added

---

## References

- **TLA+ Video Course**: Leslie Lamport's lectures on distributed systems
- **AWS Use of TLA+**: https://lamport.azurewebsites.net/tla/amazon.html
- **Raft Consensus TLA+ Spec**: https://github.com/ongardie/raft.tla
- **Knox Architecture Analysis**: `formal-verification/README.md`

---

**Last Updated**: 2025-10-24  
**Verified Configurations**: See individual `.cfg` files  
**Model Checker Version**: TLC 1.8.0+
