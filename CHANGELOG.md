# Changelog

## [2.0.0] - 2026-06-22

### Changed
- Complete rewrite from single-file to modular package architecture
- Each evasion technique is now an independent module under ghost/modules/
- Crypto utilities extracted to ghost/utils/crypto.py
- Rich console output with graceful fallback

### Added
- ghost/modules/base.py — abstract base module
- ghost/utils/crypto.py — XOR, entropy, random variable generation
- ghost/exceptions.py — typed exception hierarchy
- 17 unit tests (models, crypto, CLI)
- pyproject.toml, Makefile, CI pipeline, Dockerfile
- Documentation: ARCHITECTURE.md, USAGE.md
- Open source files: LICENSE, CONTRIBUTING, SECURITY, CHANGELOG

## [1.0.0] - 2026-06-20

### Added
- Initial release: AMSI bypass, AV evasion, process injection,
  LOLBaS, shellcode staging, EDR fingerprinting
