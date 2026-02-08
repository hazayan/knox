-------------------------- MODULE MasterKeyRotation --------------------------
(****************************************************************************)
(* TLA+ Specification for Knox Master Key Rotation Protocol                *)
(*                                                                          *)
(* This specification models the graceful master key rotation with         *)
(* backward compatibility, ensuring no decryption failures during rotation *)
(*                                                                          *)
(* Based on: pkg/crypto/rotation.go - KeyRotationManager                   *)
(*                                                                          *)
(* Key Properties to Verify:                                               *)
(*   1. No time window where valid ciphertext cannot be decrypted          *)
(*   2. Re-encryption is crash-safe and resumable                          *)
(*   3. Old cryptors removed only after all keys re-encrypted              *)
(*   4. Concurrent reads/writes during rotation maintain consistency       *)
(****************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MaxKeys,         \* Maximum number of keys in database (for bounded checking)
    MaxCryptors,     \* Maximum number of old cryptors to maintain
    KeyIDs,          \* Set of possible key IDs
    CryptorIDs       \* Set of cryptor identifiers (k1, k2, k3...)

ASSUME MaxKeys \in Nat /\ MaxKeys > 0
ASSUME MaxCryptors \in Nat /\ MaxCryptors > 0
ASSUME KeyIDs # {}
ASSUME CryptorIDs # {}

(****************************************************************************)
(* A database key has an ID and the cryptor ID used to encrypt it          *)
(****************************************************************************)
DBKey == [id: KeyIDs, encryptedWith: CryptorIDs]

VARIABLES
    currentCryptor,  \* The active cryptor for all new encryption operations
    oldCryptors,     \* Sequence of old cryptors (index 1 is most recent)
    database,        \* Set of encrypted keys in database
    reencrypting,    \* Set of keys currently being re-encrypted
    reencrypted      \* Set of keys successfully re-encrypted with current cryptor

vars == <<currentCryptor, oldCryptors, database, reencrypting, reencrypted>>

(****************************************************************************)
(* Helper Functions                                                         *)
(****************************************************************************)

\* Get all cryptors (current + old)
AllCryptors == {currentCryptor} \cup {oldCryptors[i]: i \in DOMAIN oldCryptors}

\* Check if a key can be decrypted with available cryptors
CanDecrypt(key) == key.encryptedWith \in AllCryptors

\* Get keys encrypted with a specific cryptor
KeysEncryptedWith(cryptor) == {k \in database: k.encryptedWith = cryptor}

\* Check if all keys are encrypted with current cryptor
AllKeysReencrypted == \A k \in database: k.encryptedWith = currentCryptor

\* Get keys that need re-encryption
KeysNeedingReencryption == {k \in database: k.encryptedWith # currentCryptor}

(****************************************************************************)
(* Invariants - These must ALWAYS hold                                     *)
(****************************************************************************)

TypeOK ==
    /\ currentCryptor \in CryptorIDs
    /\ oldCryptors \in Seq(CryptorIDs)
    /\ Len(oldCryptors) <= MaxCryptors
    /\ database \subseteq DBKey
    /\ reencrypting \subseteq database
    /\ reencrypted \subseteq KeyIDs

\* INV1: Every key in the database can be decrypted
\* This is the critical safety property - no data loss
NoDecryptionFailures ==
    \A k \in database: CanDecrypt(k)

\* INV2: Current cryptor is not in old cryptors list
\* Prevents confusion about which cryptor to use
CurrentNotInOld ==
    currentCryptor \notin {oldCryptors[i]: i \in DOMAIN oldCryptors}

\* INV3: Old cryptors list has unique elements
\* No duplicates in the fallback chain
UniqueOldCryptors ==
    \A i, j \in DOMAIN oldCryptors:
        i # j => oldCryptors[i] # oldCryptors[j]

\* INV4: Keys being re-encrypted exist in database
ReencryptingValid ==
    reencrypting \subseteq database

\* INV5: Re-encrypted tracking is consistent
\* If a key ID is marked as re-encrypted, the database key uses current cryptor
ReencryptedConsistency ==
    \A kid \in reencrypted:
        \E k \in database:
            /\ k.id = kid
            /\ k.encryptedWith = currentCryptor

\* Combined invariant
Invariants ==
    /\ TypeOK
    /\ NoDecryptionFailures
    /\ CurrentNotInOld
    /\ UniqueOldCryptors
    /\ ReencryptingValid
    /\ ReencryptedConsistency

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    \* Start with some keys encrypted with the initial cryptor
    /\ \E initialCryptor \in CryptorIDs:
        /\ currentCryptor = initialCryptor
        /\ oldCryptors = <<>>
        /\ database \in SUBSET [id: KeyIDs, encryptedWith: {initialCryptor}]
        /\ database # {}  \* At least one key
        /\ Cardinality(database) <= MaxKeys
    /\ reencrypting = {}
    /\ reencrypted = {}

(****************************************************************************)
(* Operations - Based on pkg/crypto/rotation.go                            *)
(****************************************************************************)

\* Write a new key (always uses current cryptor)
\* Corresponds to: Encrypt() method
WriteNewKey(kid) ==
    /\ kid \in KeyIDs
    /\ ~\E k \in database: k.id = kid  \* Key doesn't exist
    /\ Cardinality(database) < MaxKeys
    /\ database' = database \cup {[id |-> kid, encryptedWith |-> currentCryptor]}
    /\ UNCHANGED <<currentCryptor, oldCryptors, reencrypting, reencrypted>>

\* Read a key (can use any available cryptor)
\* Corresponds to: Decrypt() method - tries current then old cryptors
ReadKey(kid) ==
    /\ \E k \in database:
        /\ k.id = kid
        /\ CanDecrypt(k)  \* Verify we can decrypt it
    /\ UNCHANGED vars  \* Read-only operation

\* Rotate to a new master key
\* Corresponds to: RotateTo() or UpdateCurrentCryptor()
\* Current cryptor becomes old[1], new cryptor becomes current
RotateMasterKey(newCryptor) ==
    /\ newCryptor \in CryptorIDs
    /\ newCryptor # currentCryptor
    /\ newCryptor \notin {oldCryptors[i]: i \in DOMAIN oldCryptors}
    /\ Len(oldCryptors) < MaxCryptors
    /\ oldCryptors' = <<currentCryptor>> \o oldCryptors
    /\ currentCryptor' = newCryptor
    /\ UNCHANGED <<database, reencrypting, reencrypted>>

\* Start re-encrypting a key
\* Corresponds to: Beginning of ReencryptDB() iteration
StartReencrypt(kid) ==
    /\ \E k \in database:
        /\ k.id = kid
        /\ k.encryptedWith # currentCryptor  \* Needs re-encryption
        /\ k \notin reencrypting             \* Not already being re-encrypted
    /\ reencrypting' = reencrypting \cup {CHOOSE k \in database: k.id = kid}
    /\ UNCHANGED <<currentCryptor, oldCryptors, database, reencrypted>>

\* Complete re-encrypting a key
\* Corresponds to: UpdateKey() call in ReencryptDB()
\* This is atomic - decrypt with old cryptor, encrypt with current, update DB
CompleteReencrypt(kid) ==
    /\ \E k \in reencrypting:
        /\ k.id = kid
        /\ CanDecrypt(k)  \* Can decrypt with available cryptors
        /\ LET newKey == [id |-> kid, encryptedWith |-> currentCryptor]
           IN /\ database' = (database \ {k}) \cup {newKey}
              /\ reencrypting' = reencrypting \ {k}
              /\ reencrypted' = reencrypted \cup {kid}
    /\ UNCHANGED <<currentCryptor, oldCryptors>>

\* Crash during re-encryption (lose reencrypting state but database intact)
\* Models crash-safety - can resume re-encryption after crash
CrashDuringReencrypt ==
    /\ reencrypting # {}
    /\ reencrypting' = {}
    /\ UNCHANGED <<currentCryptor, oldCryptors, database, reencrypted>>

\* Remove an old cryptor (only safe when no keys use it)
\* Corresponds to: RemoveOldCryptor()
RemoveOldCryptor ==
    /\ Len(oldCryptors) > 0
    /\ LET oldestCryptor == oldCryptors[Len(oldCryptors)]
       IN /\ KeysEncryptedWith(oldestCryptor) = {}  \* No keys use it
          /\ oldCryptors' = SubSeq(oldCryptors, 1, Len(oldCryptors) - 1)
    /\ UNCHANGED <<currentCryptor, database, reencrypting, reencrypted>>

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

Next ==
    \/ \E kid \in KeyIDs: WriteNewKey(kid)
    \/ \E kid \in KeyIDs: ReadKey(kid)
    \/ \E newCryptor \in CryptorIDs: RotateMasterKey(newCryptor)
    \/ \E kid \in KeyIDs: StartReencrypt(kid)
    \/ \E kid \in KeyIDs: CompleteReencrypt(kid)
    \/ CrashDuringReencrypt
    \/ RemoveOldCryptor

(****************************************************************************)
(* Specification                                                            *)
(****************************************************************************)

Spec == Init /\ [][Next]_vars

(****************************************************************************)
(* Temporal Properties                                                      *)
(****************************************************************************)

\* Safety: We can always decrypt every key
AlwaysCanDecrypt == []NoDecryptionFailures

\* Safety: Current cryptor never appears in old cryptors
AlwaysDistinctCryptors == []CurrentNotInOld

\* Liveness: After rotation, we eventually finish re-encryption
\* (under weak fairness - if re-encryption is continuously enabled, it eventually happens)
EventualReencryption ==
    WF_vars(CompleteReencrypt(kid)) =>
        (KeysNeedingReencryption # {} ~> KeysNeedingReencryption = {})

\* Liveness: We can eventually remove old cryptors after re-encryption completes
EventualCleanup ==
    WF_vars(RemoveOldCryptor) =>
        (AllKeysReencrypted /\ Len(oldCryptors) > 0 ~> Len(oldCryptors) = 0)

\* Safety: Crash recovery doesn't violate invariants
CrashSafety ==
    []((reencrypting # {}) => <>Invariants)

(****************************************************************************)
(* Additional Properties for Testing                                       *)
(****************************************************************************)

\* After a rotation, new writes use the new cryptor
NewWritesUseCurrentCryptor ==
    [][\E kid \in KeyIDs: WriteNewKey(kid) =>
        \E k \in database': k.id = kid /\ k.encryptedWith = currentCryptor']_vars

\* Old cryptor can only be removed when safe
SafeRemoval ==
    [][RemoveOldCryptor =>
        \A k \in database:
            k.encryptedWith # oldCryptors[Len(oldCryptors)]]_vars

==============================================================================

(****************************************************************************)
(* Model Checking Configuration Notes                                      *)
(*                                                                          *)
(* Recommended configuration:                                              *)
(*   MaxKeys = 3-4 (small for tractability)                                *)
(*   MaxCryptors = 2-3                                                     *)
(*   KeyIDs = {k1, k2, k3}                                                 *)
(*   CryptorIDs = {c1, c2, c3}                                             *)
(*                                                                          *)
(* This will explore ~10^6 states and verify:                              *)
(*   - No decryption failures during rotation                              *)
(*   - Crash-safety of re-encryption                                       *)
(*   - Proper cleanup of old cryptors                                      *)
(*   - Concurrent read/write consistency                                   *)
(****************************************************************************)
