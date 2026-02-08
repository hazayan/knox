------------------------ MODULE KeyVersionStateMachine ------------------------
(****************************************************************************)
(* TLA+ Specification for Knox Key Version State Machine                   *)
(*                                                                          *)
(* This specification models the core invariants and state transitions     *)
(* of key versions in the Knox secret management system.                   *)
(*                                                                          *)
(* Based on: pkg/types/knox.go - KeyVersionList and VersionStatus          *)
(*                                                                          *)
(* Key Invariants to Verify:                                               *)
(*   1. Exactly one Primary version exists at all times                    *)
(*   2. Version IDs are unique within a key                                *)
(*   3. Only valid state transitions are allowed                           *)
(*   4. Version hash consistency is maintained                             *)
(****************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MaxVersions,     \* Maximum number of versions to model (for bounded checking)
    VersionIDs       \* Set of possible version IDs

ASSUME MaxVersions \in Nat /\ MaxVersions > 0
ASSUME VersionIDs # {}

(****************************************************************************)
(* Version Status Constants - mapping from Go code                         *)
(****************************************************************************)
CONSTANTS Primary, Active, Inactive

(****************************************************************************)
(* A version is a record with an ID and status                             *)
(****************************************************************************)
Version == [id: VersionIDs, status: {Primary, Active, Inactive}]

VARIABLES
    versions,        \* Set of versions (subset of Version)
    versionHash      \* Hash of active versions (for integrity checking)

vars == <<versions, versionHash>>

(****************************************************************************)
(* Helper Functions                                                         *)
(****************************************************************************)

\* Get all versions with a specific status
VersionsWithStatus(status) == {v \in versions: v.status = status}

\* Get primary version (should be exactly one)
PrimaryVersions == VersionsWithStatus(Primary)

\* Get active versions
ActiveVersions == VersionsWithStatus(Active)

\* Get inactive versions
InactiveVersions == VersionsWithStatus(Inactive)

\* Get all version IDs
VersionIDSet == {v.id: v \in versions}

\* Compute hash of active versions (Primary + Active)
\* In reality this is SHA256; we model it as the set of IDs
ComputeVersionHash == VersionIDSet \ {v.id: v \in InactiveVersions}

\* Find a version by ID
FindVersion(vid) == CHOOSE v \in versions: v.id = vid

\* Check if a version ID exists
VersionExists(vid) == \E v \in versions: v.id = vid

(****************************************************************************)
(* Invariants - These must ALWAYS hold                                     *)
(****************************************************************************)

\* INV1: Exactly one Primary version must exist
TypeOK ==
    /\ versions \subseteq Version
    /\ versionHash \subseteq VersionIDs

SinglePrimaryInvariant ==
    Cardinality(PrimaryVersions) = 1

\* INV2: Version IDs must be unique (implicitly true since versions is a set)
UniqueVersionIDs ==
    Cardinality(versions) = Cardinality(VersionIDSet)

\* INV3: Version hash matches computed hash
VersionHashConsistency ==
    versionHash = ComputeVersionHash

\* INV4: At least one version exists (Primary)
NonEmptyVersionList ==
    versions # {}

\* Combined invariant
Invariants ==
    /\ TypeOK
    /\ SinglePrimaryInvariant
    /\ UniqueVersionIDs
    /\ VersionHashConsistency
    /\ NonEmptyVersionList

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    \* Start with a single Primary version
    \E vid \in VersionIDs:
        /\ versions = {[id |-> vid, status |-> Primary]}
        /\ versionHash = {vid}

(****************************************************************************)
(* State Transitions - Based on pkg/types/knox.go KeyVersionList.Update()  *)
(****************************************************************************)

\* Add a new version with Active status
\* Corresponds to: POST /v0/keys/{keyID}/versions/
AddVersion(vid) ==
    /\ vid \notin VersionIDSet                      \* Must be new ID
    /\ Cardinality(versions) < MaxVersions          \* Bounded model
    /\ versions' = versions \cup {[id |-> vid, status |-> Active]}
    /\ versionHash' = versionHash \cup {vid}

\* Promote an Active version to Primary
\* Automatically demotes current Primary to Active
\* Corresponds to: PUT /v0/keys/{keyID}/versions/{versionID}/ with status=Primary
PromoteToPrimary(vid) ==
    /\ VersionExists(vid)
    /\ FindVersion(vid).status = Active             \* Can only promote Active
    /\ LET oldPrimary == CHOOSE v \in versions: v.status = Primary
           newVersions == (versions \ {oldPrimary, FindVersion(vid)})
                         \cup {[id |-> oldPrimary.id, status |-> Active]}
                         \cup {[id |-> vid, status |-> Primary]}
       IN /\ versions' = newVersions
          /\ versionHash' = ComputeVersionHash      \* Recompute hash

\* Demote an Active version to Inactive
\* Corresponds to: PUT /v0/keys/{keyID}/versions/{versionID}/ with status=Inactive
DemoteToInactive(vid) ==
    /\ VersionExists(vid)
    /\ FindVersion(vid).status = Active             \* Can only demote Active
    /\ LET v == FindVersion(vid)
           newVersions == (versions \ {v}) \cup {[id |-> vid, status |-> Inactive]}
       IN /\ versions' = newVersions
          /\ versionHash' = versionHash \ {vid}     \* Remove from hash

\* Restore an Inactive version to Active
\* Corresponds to: PUT /v0/keys/{keyID}/versions/{versionID}/ with status=Active
RestoreToActive(vid) ==
    /\ VersionExists(vid)
    /\ FindVersion(vid).status = Inactive           \* Can only restore Inactive
    /\ LET v == FindVersion(vid)
           newVersions == (versions \ {v}) \cup {[id |-> vid, status |-> Active]}
       IN /\ versions' = newVersions
          /\ versionHash' = versionHash \cup {vid}  \* Add back to hash

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

Next ==
    \/ \E vid \in VersionIDs: AddVersion(vid)
    \/ \E vid \in VersionIDSet: PromoteToPrimary(vid)
    \/ \E vid \in VersionIDSet: DemoteToInactive(vid)
    \/ \E vid \in VersionIDSet: RestoreToActive(vid)

(****************************************************************************)
(* Specification                                                            *)
(****************************************************************************)

Spec == Init /\ [][Next]_vars

(****************************************************************************)
(* Temporal Properties                                                      *)
(****************************************************************************)

\* Safety: The single primary invariant is never violated
AlwaysSinglePrimary == []SinglePrimaryInvariant

\* Safety: Version hash is always consistent
AlwaysConsistentHash == []VersionHashConsistency

==============================================================================
