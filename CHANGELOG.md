# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-03-30

### Added

- Initial release of codewash
- **Scanner module**: Recursive directory traversal with relevant file detection
  - Recognizes 13+ file extensions and special filenames
  - Skips irrelevant directories (`.git`, `node_modules`, etc.)
  - Never follows symlinks
  - Binary file detection

- **Detector module**: Pattern-based sensitive data detection
  - 10 built-in detection categories:
    - IP addresses (private IPv4, public IPv4, CIDR notation)
    - Internal domains (`.internal`, `.corp`, `.local`, etc.)
    - Container registry URLs (private registries, AWS ECR)
    - Email addresses
    - API keys and tokens (AWS, GitHub, GitLab)
    - Passwords in various formats
    - Private key blocks (RSA, EC, OpenSSH)
    - AWS resources (ARNs, S3 URIs, ECR)
    - Internal hostnames (service-env-number pattern)
    - Git remote URLs (private instances only)
  - Allowlist for 20+ known-safe values
  - Configurable denylist for force-flagging
  - Comment line handling (optional)

- **Replacer module**: Consistent anonymization with reversal
  - Global mapping across repository
  - Syntactically valid replacement values
  - RFC 5737 TEST-NET-2 compliance for IP addresses
  - Reversible via `.codewash-map.json` mapping file
  - In-place restoration support

- **Config module**: YAML-based configuration
  - Custom regex patterns with templated replacements
  - Allowlist and denylist management
  - Extra file extensions
  - Path exclusion with glob patterns
  - Comment scanning toggle

- **CLI**: Typer-based command-line interface
  - `scan` — Dry run with text/JSON output
  - `anon` — Create anonymized copy
  - `restore` — Restore from mapping file
  - `init` — Generate template config file
  - Rich terminal formatting with colors and progress bars

- **Comprehensive test suite**: 145 tests covering all modules
  - Scanner tests (file discovery, symlinks, binary detection)
  - Detector tests (pattern matching, edge cases)
  - Replacer tests (consistency, idempotency, reversibility)
  - Config tests (YAML parsing, validation)
  - Integration tests with realistic fixtures

- **Documentation**
  - Detailed README with quick start
  - Pattern reference guide
  - CLI command documentation
  - Contributing guidelines
  - Example `.codewash.yaml` configurations

### Features

- Zero network access — runs completely offline
- No external service dependencies
- Configurable for DevOps-focused stacks
- Suitable for CI/CD pipelines with JSON output
- Reversible anonymization for debugging

### Technical Highlights

- Pure Python 3.10+ implementation
- Type-hinted throughout
- Minimal dependencies (typer, rich, pyyaml)
- Fast performance (1000+ files in <5 seconds)
- Atomic operations (original repo always preserved)

---

## Unreleased (Future Work)

### Planned Features

- Profile system for different tech stacks (DevOps, backend, data engineering)
- YAML/JSON structure-aware detection
- Encrypted mapping files
- Diff-style output mode
- Watch mode for automatic anonymization
- Plugin system for custom detectors
- Pre-commit hook integration
- GitHub Action for CI/CD

### Ideas

- Web interface for visualization
- Database credential detection improvements
- Kubernetes secret detection
- Terraform variable handling
- Docker image layer analysis
