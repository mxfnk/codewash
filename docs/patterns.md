# codewash – Pattern Reference

This document describes all built-in detection patterns.

## Categories

### `ip_address`
Private (RFC 1918) and public IPv4 addresses, including CIDR notation.

- `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`
- Any `x.x.x.x` pattern not on the allowlist
- CIDR suffixes: `/8`, `/16`, `/24`, etc.
- **Allowlisted:** `127.0.0.1`, `0.0.0.0`

### `domain`
Internal domain names with private TLD suffixes.

- Suffixes: `.internal`, `.corp`, `.local`, `.intra`, `.private`, `.company`
- **Allowlisted:** `localhost`, `example.com`, `example.org`, `example.net`

### `registry_url`
Private container registry URLs.

- Pattern: `registry.host/path/image:tag`
- AWS ECR: `123456789012.dkr.ecr.region.amazonaws.com/repo`
- **Allowlisted (not replaced):** `docker.io`, `gcr.io`, `ghcr.io`, `registry.k8s.io`, `quay.io`, `mcr.microsoft.com`

### `email`
Email addresses in configuration values.

- Standard `user@domain.tld` pattern
- **Allowlisted:** `noreply@*`, `no-reply@*`, `*@example.com`

### `api_key`
API keys, tokens, and credentials.

- Key-value assignments: `api_key: ...`, `access_token: ...`, `secret_key: ...`
- AWS Access Keys: `AKIA...` or `ASIA...` + 16 chars
- GitHub Tokens: `ghp_`, `gho_`, `ghs_`, `ghr_`
- GitLab Tokens: `glpat-`

### `password`
Password values in assignments and connection strings.

- Keywords: `password`, `passwd`, `pass`, `pwd`, `secret`
- Connection strings: `postgresql://user:PASSWORD@host`

### `private_key`
PEM-encoded private key blocks.

- `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`
- The entire block until `-----END ... PRIVATE KEY-----` is replaced

### `aws_resource`
AWS resource identifiers.

- ARNs: `arn:aws:service:region:account:resource`
- S3 URIs: `s3://bucket-name/path`
- ECR URLs: see `registry_url`

### `internal_hostname`
Host names matching the `{service}-{env}-{number}` pattern.

- Environments: `prod`, `staging`, `dev`, `test`, `qa`, `uat`
- Examples: `db-prod-01`, `app-staging-03`, `redis-dev-02`

### `git_remote`
Git remote URLs pointing to private/self-hosted instances.

- SSH: `git@gitlab.company.com:group/repo.git`
- HTTPS: `https://git.company.com/group/repo.git`
- **Allowlisted:** `github.com`, `gitlab.com`, `bitbucket.org`

---

## Allowlist (built-in)

These values are never anonymized:

| Value | Reason |
|---|---|
| `127.0.0.1`, `0.0.0.0`, `::1` | Loopback / unspecified addresses |
| `localhost` | Local hostname |
| `example.com`, `example.org`, `example.net` | RFC 2606 example domains |
| `docker.io`, `gcr.io`, `ghcr.io`, `registry.k8s.io`, `quay.io`, `mcr.microsoft.com` | Public container registries |
| `github.com`, `gitlab.com`, `bitbucket.org` | Public git hosts |
| `noreply@*`, `no-reply@*` | Generic no-reply email prefixes |

---

## Custom Patterns (`.codewash.yaml`)

You can add your own regex patterns:

```yaml
additional_patterns:
  - name: "jira-keys"
    pattern: "(?:MYPROJ|DEVOPS)-\\d+"
    replacement: "TICKET-{n}"
```

The `{n}` placeholder is replaced with an incrementing counter starting at 1.
