# Knox Formal Verification - Document Index

Quick navigation for all formal verification documentation.

## 🚀 Start Here

- **[QUICKSTART.md](QUICKSTART.md)** - 5-minute setup and first model check
- **[README.md](README.md)** - Comprehensive overview and guide

## 📋 Reference Documentation

- **[PROPERTIES.md](PROPERTIES.md)** - All verified properties with security impact analysis
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common errors and solutions

## 🔧 Configuration & Tooling

- **[tla/Makefile](tla/Makefile)** - Automated model checking commands
- **[github-workflow-example.yml](github-workflow-example.yml)** - CI/CD integration template

## 📊 TLA+ Specifications

### Phase 1: Key Version State Machine
- **Spec**: [tla/KeyVersionStateMachine.tla](tla/KeyVersionStateMachine.tla)
- **Config**: [tla/KeyVersionStateMachine.cfg](tla/KeyVersionStateMachine.cfg)
- **Verifies**: Single primary invariant, version transitions, hash consistency
- **State Space**: ~50K states, ~30 seconds

### Phase 2: Master Key Rotation Protocol
- **Spec**: [tla/MasterKeyRotation.tla](tla/MasterKeyRotation.tla)
- **Config**: [tla/MasterKeyRotation.cfg](tla/MasterKeyRotation.cfg)
- **Verifies**: No decryption failures, crash-safety, graceful rotation
- **State Space**: ~500K states, ~60 seconds

### Phase 3: Distributed Locking
- **Spec**: [tla/DistributedLocking.tla](tla/DistributedLocking.tla)
- **Config**: [tla/DistributedLocking.cfg](tla/DistributedLocking.cfg)
- **Verifies**: Mutual exclusion, deadlock-freedom, session expiry
- **State Space**: ~1M states, ~90 seconds

## 🎯 Common Tasks

| Task | Command |
|------|---------|
| Run all checks | `cd tla && make check-all` |
| Check single spec | `cd tla && make check-version` |
| Clean outputs | `cd tla && make clean` |
| Verify TLC install | `cd tla && make test-install` |

## 📖 Learning Path

1. **New to TLA+**: Start with [QUICKSTART.md](QUICKSTART.md), then https://learntla.com/
2. **Understanding specs**: Read [README.md](README.md) "What We're Verifying" section
3. **Interpreting results**: See [README.md](README.md) "Interpreting Results"
4. **Debugging failures**: Use [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
5. **Deep dive**: Study individual `.tla` files (heavily commented)

## 🔗 External Resources

- **TLA+ Homepage**: https://lamport.azurewebsites.net/tla/tla.html
- **Learn TLA+**: https://learntla.com/
- **TLA+ Toolbox**: https://github.com/tlaplus/tlaplus/releases
- **Video Course**: Leslie Lamport's TLA+ lectures on YouTube
- **Examples**: https://github.com/tlaplus/Examples

## 📞 Support

- **Knox issues**: File in main repository
- **TLA+ help**: https://groups.google.com/g/tlaplus
- **Spec questions**: See inline comments in `.tla` files

---

**Quick Links**:
[Setup](QUICKSTART.md) | 
[Guide](README.md) | 
[Properties](PROPERTIES.md) | 
[Troubleshooting](TROUBLESHOOTING.md) | 
[Specs](tla/)
