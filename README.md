<div align="center">

# 🫧 codewash

**Anonymize code repositories for safe AI processing**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-145%20passing-brightgreen.svg)](#)

</div>

`codewash` is a CLI tool for macOS and Linux that strips sensitive information from infrastructure code so it can be safely processed by AI agents — without leaking IP addresses, internal domains, credentials, or organization-specific details.

**Designed for DevOps code:** GitLab CI pipelines, Kubernetes manifests, Helm charts, Dockerfiles, Bash and Python scripts, Terraform configurations, and general infrastructure config files.

---

## Why codewash?

When you paste infra code into an AI assistant, you risk exposing:

- Internal IP addresses and hostnames
- API keys, tokens, and passwords
- Private container registry URLs
- Internal domain names and git remotes
- AWS account IDs, ARNs, and S3 bucket names

`codewash` solves this by creating a **sanitized copy** of your repository, replacing every sensitive value with a synthetic but syntactically valid placeholder. Replacements are **globally consistent** — the same original value always maps to the same replacement — and **reversible** via a mapping file.

---

## Features

- **10 detection categories** out of the box: IP addresses, domains, registry URLs, emails, API keys, passwords, private keys, AWS resources, internal hostnames, and git remotes
- **Allowlist** for known-safe values (`docker.io`, `github.com`, `127.0.0.1`, `example.com`, …)
- **Consistent replacements** across all files in a repository
- **Reversible** — restore originals from the mapping file
- **Zero network access** — runs fully offline
- **Configurable** via `.codewash.yaml` — add custom patterns, extend the allowlist, exclude paths
- **Multiple output formats** — human-readable terminal output or JSON for CI pipelines
- **RFC 5737 compliant** — replacement IPs use the TEST-NET-2 range (`198.51.100.x`)

---

## Installation

### Option A — `pipx` (recommended for macOS)

[pipx](https://pipx.pypa.io) installs CLI tools into isolated environments and makes them available system-wide:

```bash
pipx install git+https://github.com/mxfnk/codewash.git
```

Install `pipx` first if needed: `brew install pipx && pipx ensurepath`

### Option B — virtual environment

```bash
git clone https://github.com/mxfnk/codewash.git
cd codewash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

> **Note:** On macOS, `pip install` into the system or Homebrew Python is blocked by default (PEP 668). Always use a virtual environment or `pipx`.

**Requirements:** Python 3.10+

---

## Quick Start

### Scan — see what would be anonymized (dry run)

```bash
codewash scan ./my-infra-repo
```

```
══════════════════════ codewash scan ══════════════════════
Scanning: ./my-infra-repo

Found 23 relevant files

  ▸ .gitlab-ci.yml
    ⚠ [API_KEY ]  L11: sk_live_a1b2c3d4e5f6g7h8i9j0
    ⚠ [EMAIL   ]  L12: admin@mycompany.de
    ⚠ [IP      ]  L13: 192.168.10.42
    ⚠ [HOSTNAME]  L9:  db-prod-01

  ▸ k8s/deployment.yaml
    ⚠ [AWS     ]  L15: 123456789012.dkr.ecr.eu-central-1.amazonaws.com
    ⚠ [PASSWORD]  L18: SuperSecret123

─── Summary ───
  Files scanned:  23
  Findings:       42
```

### Anonymize — create a sanitized copy

```bash
codewash anon ./my-infra-repo
# Output written to: ./my-infra-repo_anon/
```

Or specify an output directory:

```bash
codewash anon ./my-infra-repo --output /tmp/safe-copy
```

The anonymized directory is safe to share with AI assistants.

### Restore — get your originals back

```bash
codewash restore ./my-infra-repo_anon
```

This reads the `.codewash-map.json` in the anonymized directory and restores all original values in-place.

### Initialize a config file

```bash
codewash init
# Creates .codewash.yaml in the current directory
```

---

## Detection Categories

| Category            | Examples detected                                    | Replacement format                       |
| ------------------- | ---------------------------------------------------- | ---------------------------------------- |
| `ip_address`        | `192.168.1.5`, `10.0.0.1/24`                         | `198.51.100.{n}`                         |
| `domain`            | `api.corp.internal`, `db.local`                      | `service-{n}.example.internal`           |
| `registry_url`      | `registry.mycompany.de/app:latest`                   | `registry.example.com/project-{n}/image` |
| `email`             | `admin@mycompany.de`                                 | `user-{n}@example.com`                   |
| `api_key`           | `glpat-xxx`, `ghp_xxx`, `AKIAXXXXXX`                 | `REDACTED_API_KEY_{n:04d}`               |
| `password`          | `password: hunter2`, `pg://user:pw@host`             | `REDACTED_PASSWORD_{n:04d}`              |
| `private_key`       | `-----BEGIN RSA PRIVATE KEY-----`                    | `# REDACTED_PRIVATE_KEY`                 |
| `aws_resource`      | `arn:aws:iam::123456789012:role/x`, `s3://my-bucket` | `arn:aws:s3:::example-bucket-{n}`        |
| `internal_hostname` | `db-prod-01`, `app-staging-03`                       | `host-anon-{n:02d}`                      |
| `git_remote`        | `git@gitlab.mycompany.de:org/repo.git`               | `git@git.example.com:org/repo-{n}.git`   |

**Never anonymized (built-in allowlist):** `127.0.0.1`, `0.0.0.0`, `localhost`, `::1`, `example.com/org/net`, `docker.io`, `gcr.io`, `ghcr.io`, `registry.k8s.io`, `quay.io`, `mcr.microsoft.com`, `github.com`, `gitlab.com`, `bitbucket.org`, `noreply@*`

---

## Configuration

Create a `.codewash.yaml` in your repository (or run `codewash init`):

```yaml
# Add custom detection patterns
additional_patterns:
  - name: "jira-keys"
    pattern: "(?:MYPROJ|DEVOPS|INFRA)-\\d+"
    replacement: "PROJECT-{n}"

# Values that should NEVER be anonymized
allowlist:
  - "api.stripe.com"
  - "hooks.slack.com"

# Values that should ALWAYS be anonymized (even without a pattern match)
denylist:
  - "mycompany"
  - "secret-project-name"

# Additional file extensions to scan
extra_extensions:
  - "j2"
  - "tpl"

# Paths to skip (glob patterns)
exclude_paths:
  - "test/**"
  - "fixtures/**"

# Also scan comment lines (default: false)
scan_comments: false
```

---

## CLI Reference

```
codewash scan <DIR> [OPTIONS]

  Scan a directory and report findings without making changes (dry run).

  Options:
    -v, --verbose         Show detailed findings per file
    -c, --config FILE     Path to .codewash.yaml
    -f, --format TEXT     Output format: text (default) or json

codewash anon <SOURCE> [OPTIONS]

  Create an anonymized copy of SOURCE.

  Options:
    -o, --output DIR      Output directory (default: <SOURCE>_anon)
    -c, --config FILE     Path to .codewash.yaml
    --force               Overwrite existing output directory

codewash restore <ANON_DIR> [OPTIONS]

  Restore original values from the mapping file.

  Options:
    -m, --map FILE        Path to mapping file (default: <ANON_DIR>/.codewash-map.json)

codewash init [DIR]

  Write an annotated .codewash.yaml to DIR (default: current directory).
```

**Exit codes:** `0` = success, `1` = error, `2` = findings found (scan only)

---

## The Mapping File

Every `codewash anon` run writes a `.codewash-map.json` to the output directory:

```json
[
  {
    "original": "192.168.1.50",
    "replacement": "198.51.100.1",
    "category": "ip_address",
    "files": ["deploy/service.yaml", ".gitlab-ci.yml"]
  },
  {
    "original": "sk_live_abc123...",
    "replacement": "REDACTED_API_KEY_0001",
    "category": "api_key",
    "files": [".gitlab-ci.yml"]
  }
]
```

Keep this file private — it contains your original secrets.

---

## File Types Scanned

**Extensions:** `yml`, `yaml`, `sh`, `bash`, `py`, `rb`, `toml`, `ini`, `cfg`, `conf`, `tf`, `hcl`, `json`, `env`, `properties`

**Special filenames:** `Dockerfile`, `docker-compose`, `Makefile`, `Vagrantfile`, `.env`, `.gitlab-ci`, `Jenkinsfile`, `skaffold`, `kustomization`

**Always skipped:** `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `.terraform`, `vendor`, `.tox`, `.mypy_cache`, `.ruff_cache`

Binary files are automatically detected and skipped. Symlinks are never followed.

---

## Use in CI

The `--format json` flag makes `codewash scan` suitable for CI pipelines:

```yaml
# .gitlab-ci.yml example
check-sensitive-data:
  script:
    - pip install codewash
    - codewash scan . --format json | tee scan-report.json
  artifacts:
    paths: [scan-report.json]
  allow_failure: true # exit code 2 when findings exist
```

---

## Development

```bash
git clone https://github.com/your-username/codewash.git
cd codewash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/
mypy src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

## License

MIT — see [LICENSE](LICENSE).

## codewash
