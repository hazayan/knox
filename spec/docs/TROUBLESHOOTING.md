# TLA+ Model Checking Troubleshooting Guide

Common issues and solutions when model checking Knox specifications.

## Installation Issues

### "TLC not found" Error

```
make: /usr/local/lib/tla2tools.jar: No such file or directory
```

**Solution**:
```bash
# Download TLC
wget https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
     -O /tmp/tla2tools.jar

# Run with custom path
make check-all TLC_JAR=/tmp/tla2tools.jar

# Or install system-wide
sudo mv /tmp/tla2tools.jar /usr/local/lib/
```

### "Java not found" or Wrong Version

```
bash: java: command not found
```

**Solution**:
```bash
# Check version
java -version

# Install Java 11+ (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install openjdk-17-jre

# macOS
brew install openjdk@17
```

### TLC Fails to Start

```
Error: Could not find or load main class tlc2.TLC
```

**Solution**:
```bash
# Verify JAR is valid
unzip -t /usr/local/lib/tla2tools.jar | head

# Re-download if corrupted
rm /usr/local/lib/tla2tools.jar
wget https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
     -O /usr/local/lib/tla2tools.jar
```

---

## Model Checking Errors

### Parse Errors

```
Parsing or semantic analysis failed.
Unknown operator: `SomeFunction'
```

**Causes**:
1. Typo in operator name
2. Missing module EXTENDS
3. Prime (') on wrong side of operator

**Solution**:
```tla
\* WRONG
SomeFunction' == ...

\* RIGHT
SomeFunction == ...
variable' = ...
```

### "ASSUME Failed"

```
Assumption line 23 is false.
ASSUME MaxVersions \in Nat /\ MaxVersions > 0
```

**Solution**: Check `.cfg` file has correct constant definition:
```
CONSTANTS
    MaxVersions = 4  \* Must be positive integer
```

### "Deadlock Detected"

```
Deadlock reached.
State 1: ...
State 2: <deadlock>
```

**Meaning**: Model reached a state where no actions are enabled.

**Debug**:
1. Check if this is expected terminal state
2. Add weak fairness: `WF_vars(Next)`
3. Check enabling conditions on actions

### "Invariant Violated"

```
Error: Invariant SinglePrimaryInvariant is violated.
The behavior up to this point is:
State 1: <Initial predicate>
  /\ versions = { [id |-> v1, status |-> Primary] }
  
State 2: <AddVersion(v2) line 145>
  /\ versions = { [id |-> v1, status |-> Primary],
                  [id |-> v2, status |-> Primary] }  \* BUG!
```

**This is the intended behavior** - TLC found a bug in your spec or code design!

**How to fix**:
1. **Read the trace**: Understand sequence of operations
2. **Identify the bug**: Which action violated the invariant?
3. **Fix the spec**: Add preconditions to prevent invalid transitions
4. **Update code**: Ensure implementation matches corrected spec

Example fix:
```tla
\* BEFORE (buggy)
AddVersion(vid) ==
    /\ versions' = versions \cup {[id |-> vid, status |-> Primary]}
    
\* AFTER (fixed)
AddVersion(vid) ==
    /\ versions' = versions \cup {[id |-> vid, status |-> Active]}  \* Not Primary!
```

---

## Performance Issues

### "Model Checking Takes Forever"

```
TLC running for hours, millions of states...
```

**Solutions**:

1. **Reduce state space** (`.cfg` file):
   ```
   MaxKeys = 2          \* Instead of 4
   MaxVersions = 3      \* Instead of 5
   Nodes = {n1, n2}     \* Instead of {n1, n2, n3, n4}
   ```

2. **Add state constraints**:
   ```tla
   CONSTRAINT Cardinality(database) <= 3
   CONSTRAINT time <= 5
   ```

3. **Use symmetry** (if applicable):
   ```
   SYMMETRY KeyIDSymmetry
   ```
   
   Define in spec:
   ```tla
   KeyIDSymmetry == Permutations(KeyIDs)
   ```

4. **Increase workers**:
   ```bash
   make check-all TLC_WORKERS=8
   ```

5. **Use depth-first search** (for specific bugs):
   ```
   TLC_FLAGS="-dfid 20"  # Depth-first to depth 20
   ```

### "Out of Memory"

```
Java heap space
java.lang.OutOfMemoryError
```

**Solutions**:

1. **Increase heap size**:
   ```bash
   JAVA_OPTS="-Xmx8G" make check-all
   ```
   
   Or edit `Makefile`:
   ```makefile
   TLC_FLAGS = -Xmx8G -workers 4
   ```

2. **Reduce state space** (see above)

3. **Use disk-based mode**:
   ```
   TLC_FLAGS="-tool -modelcheck -offload 100000"
   ```

---

## Semantic Issues

### "Choose with empty set"

```
Attempted to choose from empty set.
```

**Cause**: `CHOOSE x \in S : P(x)` where S is empty or no x satisfies P.

**Debug**:
```tla
\* WRONG
FindVersion(vid) == CHOOSE v \in versions: v.id = vid

\* Problem: What if vid doesn't exist in versions?

\* RIGHT
FindVersion(vid) ==
    IF \E v \in versions: v.id = vid
    THEN CHOOSE v \in versions: v.id = vid
    ELSE [id |-> vid, status |-> Inactive]  \* Default value
```

### "Function applied to value outside domain"

```
Attempted to apply function to value not in its domain.
```

**Cause**: Accessing `f[x]` where `x \notin DOMAIN f`

**Debug**:
```tla
\* WRONG
locks[keyID].holder  \* What if keyID not in locks?

\* RIGHT
\* Initialize all keys in Init:
locks = [k \in KeyIDs |-> [holder |-> NoLockHolder, ...]]

\* Or check first:
IF keyID \in DOMAIN locks THEN locks[keyID].holder ELSE NoLockHolder
```

---

## Configuration File Issues

### "Constant not assigned"

```
The constant MaxVersions is not assigned a value.
```

**Solution**: Add to `.cfg` file:
```
CONSTANTS
    MaxVersions = 3
```

### "Unknown configuration value"

```
Unknown configuration parameter: INVARIAN
```

**Cause**: Typo in `.cfg` file

**Solution**: Check spelling:
```
\* WRONG
INVARIAN
    MyInvariant

\* RIGHT
INVARIANTS
    MyInvariant
```

---

## Temporal Logic Issues

### "Liveness checking not supported"

```
Cannot check liveness properties without fairness.
```

**Solution**: Add fairness to spec:
```tla
\* WRONG
Spec == Init /\ [][Next]_vars

\* RIGHT
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)
```

### "Property always violated"

```
Temporal property AlwaysSinglePrimary violated.
```

**Debug**: Distinguish safety vs. liveness:
- Safety (`[]P`): "P always holds" - violated if P ever false
- Liveness (`<>P`): "P eventually holds" - violated if P never becomes true

Check if property is correctly specified:
```tla
\* Safety: Must always hold
AlwaysSinglePrimary == []SinglePrimaryInvariant

\* Liveness: Must eventually hold
EventuallyConsistent == <>(AllKeysReencrypted)
```

---

## Debugging Strategies

### Enable Verbose Output

```bash
# Add to Makefile or run directly
java -cp $(TLC_JAR) tlc2.TLC -verbose -debug MySpec.tla
```

### Generate Error Trace

TLC automatically generates trace. To save:
```bash
make check-version 2>&1 | tee trace.txt
```

### Visualize State Graph

```bash
make visualize-version  # Requires GraphViz
```

Creates PDF showing state transitions.

### Check Specific Scenarios

Add trace constraints:
```tla
\* Only explore behaviors where v1 gets promoted
TraceConstraint ==
    \/ ~VersionExists("v1")
    \/ FindVersion("v1").status # Primary
    \/ TRUE  \* Continue after v1 is Primary
```

Add to `.cfg`:
```
CONSTRAINT TraceConstraint
```

---

## Common Specification Mistakes

### Mistake 1: Mutable vs Immutable Confusion

```tla
\* WRONG - trying to modify a record in-place
PromoteToPrimary(vid) ==
    /\ LET v == FindVersion(vid)
       IN v.status' = Primary  \* ERROR: Can't modify v

\* RIGHT - create new set with modified record
PromoteToPrimary(vid) ==
    /\ versions' = (versions \ {FindVersion(vid)})
                   \cup {[id |-> vid, status |-> Primary]}
```

### Mistake 2: Forgetting to Update All Variables

```tla
\* WRONG - forgot versionHash'
PromoteToPrimary(vid) ==
    /\ versions' = ...
    \* Missing: versionHash' = ...

\* RIGHT
PromoteToPrimary(vid) ==
    /\ versions' = ...
    /\ versionHash' = ComputeVersionHash  \* Don't forget!
```

### Mistake 3: Non-Determinism Confusion

```tla
\* This is non-deterministic - TLC tries ALL vid values
\/ \E vid \in VersionIDs: AddVersion(vid)

\* This is also fine - TLC explores all possibilities
\* That's the point of model checking!
```

### Mistake 4: Quantifier Errors

```tla
\* WRONG - quantified variable used outside scope
\E x \in S: P(x) /\ Q(x')  \* x' not valid

\* RIGHT
\E x \in S: P(x) /\ Q(someVariable')
```

---

## Getting Help

### Before Asking for Help

1. ✅ Read the error message carefully
2. ✅ Check this troubleshooting guide
3. ✅ Verify `.cfg` file syntax
4. ✅ Try reducing model size
5. ✅ Check TLA+ spec for typos

### Where to Get Help

- **TLA+ Google Group**: https://groups.google.com/g/tlaplus
- **TLA+ GitHub Discussions**: https://github.com/tlaplus/tlaplus/discussions
- **Learn TLA+ Community**: https://learntla.com/
- **Knox Team**: File an issue in knox repository

### Information to Include

When reporting issues:
- TLA+ spec (`.tla` file)
- Configuration (`.cfg` file)
- Full error output
- TLC version: `java -cp $(TLC_JAR) tlc2.TLC -h | head -n 1`
- Java version: `java -version`
- What you've already tried

---

## Quick Reference

### Syntax Cheat Sheet

```tla
\* Comments
(* Multi-line
   comments *)

\* Logic
/\  (and)
\/  (or)
~   (not)
=>  (implies)
<=> (iff)

\* Quantifiers
\A x \in S: P(x)  (forall)
\E x \in S: P(x)  (exists)

\* Sets
{1, 2, 3}           (set literal)
{x \in S: P(x)}     (set comprehension)
x \in S             (membership)
x \notin S          (not in)
S \cup T            (union)
S \cap T            (intersection)
S \ T               (difference)

\* Functions
[x \in S |-> e]     (function definition)
f[x]                (function application)
DOMAIN f            (function domain)

\* Records
[field1 |-> val1, field2 |-> val2]
r.field

\* Sequences
<<1, 2, 3>>         (sequence literal)
Len(s)              (length)
s[i]                (indexing)

\* Temporal
[]P                 (always P)
<>P                 (eventually P)
P ~> Q              (P leads to Q)
```

---

**Last Updated**: 2025-10-24
