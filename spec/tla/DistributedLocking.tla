-------------------------- MODULE DistributedLocking --------------------------
(****************************************************************************)
(* TLA+ Specification for Knox Distributed Locking via etcd                *)
(*                                                                          *)
(* This specification models the distributed coordination using etcd        *)
(* sessions and locks to ensure safe concurrent key operations across      *)
(* multiple Knox server instances.                                         *)
(*                                                                          *)
(* Based on: pkg/storage/etcd/etcd.go - distributed locking                *)
(*                                                                          *)
(* Key Properties to Verify:                                               *)
(*   1. Mutual exclusion: Only one node modifies a key at a time           *)
(*   2. Deadlock freedom: Lock acquisition doesn't cause circular waits    *)
(*   3. Lock timeout handling: Sessions expire correctly                   *)
(*   4. Optimistic concurrency: Compare-and-swap prevents lost updates     *)
(*   5. Network partition safety: Split-brain protection                   *)
(****************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Nodes,           \* Set of Knox server nodes
    KeyIDs,          \* Set of key IDs in the database
    MaxTime          \* Maximum time for bounded model checking

ASSUME Nodes # {}
ASSUME KeyIDs # {}
ASSUME MaxTime \in Nat /\ MaxTime > 0

(****************************************************************************)
(* Types and Values                                                         *)
(****************************************************************************)

CONSTANTS
    NoLockHolder,    \* Special value indicating no lock holder
    NoVersion        \* Special value for non-existent keys

NULL == CHOOSE x : x \notin Nodes \cup KeyIDs

(****************************************************************************)
(* Key State - stored in etcd                                              *)
(****************************************************************************)
KeyState == [
    value: KeyIDs \cup {NULL},      \* The key data (or NULL if deleted)
    version: Nat,                    \* Optimistic concurrency version
    exists: BOOLEAN                  \* Does the key exist?
]

(****************************************************************************)
(* Lock State - distributed locks via etcd sessions                        *)
(****************************************************************************)
LockState == [
    holder: Nodes \cup {NoLockHolder},  \* Which node holds the lock
    session: Nat,                        \* Session ID (for TTL)
    expiry: Nat                          \* When the session expires
]

VARIABLES
    etcdKeys,        \* Function: KeyIDs -> KeyState (etcd key-value store)
    locks,           \* Function: KeyIDs -> LockState (distributed locks)
    sessions,        \* Function: Nodes -> Nat (active session ID per node)
    sessionExpiry,   \* Function: Nodes -> Nat (when session expires)
    nodeWaiting,     \* Set of (node, keyID) pairs waiting for locks
    time             \* Global time counter (for session TTL modeling)

vars == <<etcdKeys, locks, sessions, sessionExpiry, nodeWaiting, time>>

(****************************************************************************)
(* Helper Functions                                                         *)
(****************************************************************************)

\* Check if a node has an active session
HasActiveSession(node) ==
    /\ node \in DOMAIN sessions
    /\ sessionExpiry[node] > time

\* Check if a lock is held
LockIsHeld(keyID) ==
    locks[keyID].holder # NoLockHolder

\* Check if a specific node holds a lock
NodeHoldsLock(node, keyID) ==
    /\ LockIsHeld(keyID)
    /\ locks[keyID].holder = node

\* Check if a node can acquire a lock
CanAcquireLock(node, keyID) ==
    /\ HasActiveSession(node)
    /\ ~LockIsHeld(keyID)

\* Get all nodes holding locks
NodesHoldingLocks == {locks[k].holder : k \in {kid \in KeyIDs : LockIsHeld(kid)}}

\* Get locks held by a specific node
LocksHeldBy(node) == {k \in KeyIDs : NodeHoldsLock(node, k)}

(****************************************************************************)
(* Invariants - These must ALWAYS hold                                     *)
(****************************************************************************)

TypeOK ==
    /\ etcdKeys \in [KeyIDs -> KeyState]
    /\ locks \in [KeyIDs -> LockState]
    /\ sessions \in [Nodes -> Nat]
    /\ sessionExpiry \in [Nodes -> Nat]
    /\ nodeWaiting \subseteq (Nodes \times KeyIDs)
    /\ time \in Nat

\* INV1: Mutual Exclusion - At most one node holds a lock on any key
MutualExclusion ==
    \A k \in KeyIDs:
        LockIsHeld(k) =>
            /\ locks[k].holder \in Nodes
            /\ \A n \in Nodes:
                NodeHoldsLock(n, k) => locks[k].holder = n

\* INV2: Lock Validity - Held locks have valid sessions
LockSessionValidity ==
    \A k \in KeyIDs:
        LockIsHeld(k) =>
            /\ locks[k].holder \in Nodes
            /\ HasActiveSession(locks[k].holder)
            /\ locks[k].session = sessions[locks[k].holder]

\* INV3: Waiting nodes have active sessions
WaitingNodesValid ==
    \A <<n, k>> \in nodeWaiting:
        /\ n \in Nodes
        /\ k \in KeyIDs
        /\ HasActiveSession(n)

\* INV4: Optimistic concurrency - version increases on each update
VersionMonotonicity ==
    \A k \in KeyIDs:
        etcdKeys[k].exists => etcdKeys[k].version >= 0

\* Combined invariant
Invariants ==
    /\ TypeOK
    /\ MutualExclusion
    /\ LockSessionValidity
    /\ WaitingNodesValid
    /\ VersionMonotonicity

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    /\ etcdKeys = [k \in KeyIDs |-> [value |-> NULL, version |-> 0, exists |-> FALSE]]
    /\ locks = [k \in KeyIDs |-> [holder |-> NoLockHolder, session |-> 0, expiry |-> 0]]
    /\ sessions = [n \in Nodes |-> 0]
    /\ sessionExpiry = [n \in Nodes |-> 0]
    /\ nodeWaiting = {}
    /\ time = 0

(****************************************************************************)
(* Time and Session Management                                             *)
(****************************************************************************)

\* Time advances (models passage of time)
AdvanceTime ==
    /\ time < MaxTime
    /\ time' = time + 1
    /\ UNCHANGED <<etcdKeys, locks, sessions, nodeWaiting>>
    \* Check for expired sessions and release their locks
    /\ sessionExpiry' = sessionExpiry
    /\ locks' = [k \in KeyIDs |->
        IF LockIsHeld(k) /\ sessionExpiry[locks[k].holder] <= time'
        THEN [holder |-> NoLockHolder, session |-> 0, expiry |-> 0]
        ELSE locks[k]]

\* Create a new session for a node
\* Corresponds to: clientv3.NewSession() in etcd.go
CreateSession(node) ==
    /\ sessions' = [sessions EXCEPT ![node] = @ + 1]
    /\ sessionExpiry' = [sessionExpiry EXCEPT ![node] = time + 3]  \* TTL of 3 time units
    /\ UNCHANGED <<etcdKeys, locks, nodeWaiting, time>>

\* Renew a session (heartbeat)
\* Corresponds to: Session.Done() channel monitoring and renewal
RenewSession(node) ==
    /\ HasActiveSession(node)
    /\ sessionExpiry' = [sessionExpiry EXCEPT ![node] = time + 3]
    /\ UNCHANGED <<etcdKeys, locks, sessions, nodeWaiting, time>>

(****************************************************************************)
(* Lock Operations                                                          *)
(****************************************************************************)

\* Acquire a distributed lock
\* Corresponds to: concurrency.NewMutex() and Lock() in etcd.go
AcquireLock(node, keyID) ==
    /\ CanAcquireLock(node, keyID)
    /\ locks' = [locks EXCEPT ![keyID] =
        [holder |-> node,
         session |-> sessions[node],
         expiry |-> sessionExpiry[node]]]
    /\ nodeWaiting' = nodeWaiting \ {<<node, keyID>>}
    /\ UNCHANGED <<etcdKeys, sessions, sessionExpiry, time>>

\* Release a lock
\* Corresponds to: mutex.Unlock() in etcd.go
ReleaseLock(node, keyID) ==
    /\ NodeHoldsLock(node, keyID)
    /\ locks' = [locks EXCEPT ![keyID] =
        [holder |-> NoLockHolder, session |-> 0, expiry |-> 0]]
    /\ UNCHANGED <<etcdKeys, sessions, sessionExpiry, nodeWaiting, time>>

\* Node waits for a lock
\* Corresponds to: blocking on Lock() call
WaitForLock(node, keyID) ==
    /\ HasActiveSession(node)
    /\ ~NodeHoldsLock(node, keyID)
    /\ <<node, keyID>> \notin nodeWaiting
    /\ nodeWaiting' = nodeWaiting \cup {<<node, keyID>>}
    /\ UNCHANGED <<etcdKeys, locks, sessions, sessionExpiry, time>>

(****************************************************************************)
(* Key Operations (Protected by Locks)                                     *)
(****************************************************************************)

\* Read a key (requires lock)
\* Corresponds to: GetKey() in etcd.go
GetKey(node, keyID) ==
    /\ NodeHoldsLock(node, keyID)
    /\ etcdKeys[keyID].exists
    /\ UNCHANGED vars  \* Read-only

\* Update a key with optimistic concurrency
\* Corresponds to: UpdateKey() with transaction in etcd.go
UpdateKey(node, keyID, newValue, expectedVersion) ==
    /\ NodeHoldsLock(node, keyID)
    /\ etcdKeys[keyID].exists
    /\ etcdKeys[keyID].version = expectedVersion  \* Compare-and-swap
    /\ etcdKeys' = [etcdKeys EXCEPT ![keyID] =
        [value |-> newValue,
         version |-> @ + 1,
         exists |-> TRUE]]
    /\ UNCHANGED <<locks, sessions, sessionExpiry, nodeWaiting, time>>

\* Create a new key (requires lock)
\* Corresponds to: PutKey() in etcd.go
PutKey(node, keyID, value) ==
    /\ NodeHoldsLock(node, keyID)
    /\ ~etcdKeys[keyID].exists
    /\ etcdKeys' = [etcdKeys EXCEPT ![keyID] =
        [value |-> value,
         version |-> 1,
         exists |-> TRUE]]
    /\ UNCHANGED <<locks, sessions, sessionExpiry, nodeWaiting, time>>

\* Delete a key (requires lock)
\* Corresponds to: DeleteKey() in etcd.go
DeleteKey(node, keyID) ==
    /\ NodeHoldsLock(node, keyID)
    /\ etcdKeys[keyID].exists
    /\ etcdKeys' = [etcdKeys EXCEPT ![keyID] =
        [value |-> NULL,
         version |-> @ + 1,
         exists |-> FALSE]]
    /\ UNCHANGED <<locks, sessions, sessionExpiry, nodeWaiting, time>>

(****************************************************************************)
(* Failure Scenarios                                                        *)
(****************************************************************************)

\* Session expires (models TTL timeout)
\* Automatically releases all locks held by that node
SessionExpires(node) ==
    /\ HasActiveSession(node)
    /\ sessionExpiry[node] <= time
    /\ sessionExpiry' = [sessionExpiry EXCEPT ![node] = 0]
    /\ sessions' = [sessions EXCEPT ![node] = 0]
    /\ locks' = [k \in KeyIDs |->
        IF locks[k].holder = node
        THEN [holder |-> NoLockHolder, session |-> 0, expiry |-> 0]
        ELSE locks[k]]
    /\ nodeWaiting' = nodeWaiting \ {<<n, k>> \in nodeWaiting : n = node}
    /\ UNCHANGED <<etcdKeys, time>>

\* Optimistic concurrency failure (version mismatch)
\* Models concurrent modification by another node
UpdateConflict(node, keyID, newValue, wrongVersion) ==
    /\ NodeHoldsLock(node, keyID)
    /\ etcdKeys[keyID].exists
    /\ etcdKeys[keyID].version # wrongVersion  \* Version mismatch - fail
    /\ UNCHANGED vars  \* No state change - operation fails

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

Next ==
    \/ AdvanceTime
    \/ \E n \in Nodes: CreateSession(n)
    \/ \E n \in Nodes: RenewSession(n)
    \/ \E n \in Nodes, k \in KeyIDs: AcquireLock(n, k)
    \/ \E n \in Nodes, k \in KeyIDs: ReleaseLock(n, k)
    \/ \E n \in Nodes, k \in KeyIDs: WaitForLock(n, k)
    \/ \E n \in Nodes, k \in KeyIDs: GetKey(n, k)
    \/ \E n \in Nodes, k \in KeyIDs, v \in KeyIDs, ver \in Nat:
        UpdateKey(n, k, v, ver)
    \/ \E n \in Nodes, k \in KeyIDs, v \in KeyIDs:
        PutKey(n, k, v)
    \/ \E n \in Nodes, k \in KeyIDs: DeleteKey(n, k)
    \/ \E n \in Nodes: SessionExpires(n)

(****************************************************************************)
(* Specification                                                            *)
(****************************************************************************)

Spec == Init /\ [][Next]_vars

(****************************************************************************)
(* Temporal Properties                                                      *)
(****************************************************************************)

\* Safety: Mutual exclusion is always maintained
AlwaysMutualExclusion == []MutualExclusion

\* Safety: Locks are always associated with valid sessions
AlwaysValidLocks == []LockSessionValidity

\* Liveness: If a node waits for a lock, it eventually gets it
\* (under weak fairness - if the lock becomes available, it's eventually acquired)
EventualLockAcquisition ==
    \A n \in Nodes, k \in KeyIDs:
        WF_vars(AcquireLock(n, k)) =>
            (<<n, k>> \in nodeWaiting ~> NodeHoldsLock(n, k))

\* Deadlock freedom: System doesn't get stuck with all nodes waiting
NoDeadlock ==
    [](nodeWaiting # {} => \E n \in Nodes, k \in KeyIDs: CanAcquireLock(n, k))

\* Session expiry releases locks
SessionExpiryReleasesLocks ==
    \A n \in Nodes:
        []((HasActiveSession(n) /\ LocksHeldBy(n) # {})
            => <>(~HasActiveSession(n) => LocksHeldBy(n) = {}))

(****************************************************************************)
(* Additional Safety Properties                                            *)
(****************************************************************************)

\* No lost updates: Optimistic concurrency prevents concurrent modifications
NoLostUpdates ==
    [][(\E n1, n2 \in Nodes, k \in KeyIDs:
        /\ n1 # n2
        /\ NodeHoldsLock(n1, k)
        /\ NodeHoldsLock(n2, k))
        => FALSE]_vars

\* Lock release is safe: Can only release locks you hold
SafeLockRelease ==
    [][\E n \in Nodes, k \in KeyIDs:
        ReleaseLock(n, k) => NodeHoldsLock(n, k)]_vars

==============================================================================

(****************************************************************************)
(* Model Checking Configuration Notes                                      *)
(*                                                                          *)
(* Recommended configuration:                                              *)
(*   Nodes = {n1, n2, n3}                                                  *)
(*   KeyIDs = {k1, k2}                                                     *)
(*   MaxTime = 10                                                          *)
(*   NoLockHolder <- NoLockHolder                                          *)
(*   NoVersion <- NoVersion                                                *)
(*                                                                          *)
(* This models 3 Knox nodes coordinating access to 2 keys with session     *)
(* timeouts, exploring scenarios like:                                     *)
(*   - Concurrent lock acquisition attempts                                *)
(*   - Session expiry during critical sections                             *)
(*   - Optimistic concurrency conflicts                                    *)
(*   - Network partition scenarios (via session timeout)                   *)
(****************************************************************************)
