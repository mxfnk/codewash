"""Central registry of all regex patterns and allowlists for codewash."""

import re
from dataclasses import dataclass, field

from codewash.models import Category


@dataclass
class PatternDef:
    """Definition of a single detection pattern."""

    name: str
    category: Category
    pattern: re.Pattern
    # Optional: function to extract the replace_value from a match
    # By default the entire match is used
    extract: callable = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Allowlist – values that are NEVER anonymized
# ---------------------------------------------------------------------------

ALLOWLIST: frozenset[str] = frozenset(
    [
        "127.0.0.1",
        "0.0.0.0",
        "localhost",
        "::1",
        "example.com",
        "example.org",
        "example.net",
        "docker.io",
        "gcr.io",
        "ghcr.io",
        "registry.k8s.io",
        "quay.io",
        "mcr.microsoft.com",
        "github.com",
        "gitlab.com",
        "bitbucket.org",
    ]
)

# Patterns that are on the allowlist (prefix-match)
ALLOWLIST_PREFIXES: tuple[str, ...] = (
    "noreply@",
    "no-reply@",
)

# Public container registries (not anonymized)
PUBLIC_REGISTRIES: frozenset[str] = frozenset(
    [
        "docker.io",
        "gcr.io",
        "ghcr.io",
        "registry.k8s.io",
        "quay.io",
        "mcr.microsoft.com",
        "index.docker.io",
    ]
)

# Public git hosts (not anonymized in git_remote)
PUBLIC_GIT_HOSTS: frozenset[str] = frozenset(
    [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
    ]
)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_IP_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
_IP_PATTERN = rf"(?:{_IP_OCTET}\.){{3}}{_IP_OCTET}"

# Context that suggests a version number rather than an IP
_VERSION_CONTEXT_RE = re.compile(
    r"(?:version|tag|image|nginx|alpine|debian|ubuntu|redis|postgres|python|node|java)"
    r"[:\s\"'/-]+"
    + _IP_PATTERN,
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# IP Addresses
# ---------------------------------------------------------------------------

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"

_PRIVATE_IP_RE = re.compile(
    rf"\b(?:"
    rf"10\.{_OCTET}\.{_OCTET}\.{_OCTET}"
    rf"|172\.(?:1[6-9]|2\d|3[01])\.{_OCTET}\.{_OCTET}"
    rf"|192\.168\.{_OCTET}\.{_OCTET}"
    rf")(?:/\d{{1,2}})?\b",
    re.IGNORECASE,
)

_PUBLIC_IP_RE = re.compile(
    rf"\b{_IP_PATTERN}(?:/\d{{1,2}})?\b",
)

# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

_INTERNAL_DOMAIN_RE = re.compile(
    r"\b(?:https?://)?(?:[\w.-]+\.)"
    r"(?:internal|corp|local|intra|private|company)"
    r"(?:/[^\s\"'`]*)?\b",
    re.IGNORECASE,
)

# Generic domain in assignment context: host: something.company.tld
_GENERIC_DOMAIN_ASSIGNMENT_RE = re.compile(
    r"(?:^|[\s\"':=])"
    r"((?:https?://)?[\w-]+(?:\.[\w-]+){2,}"
    r"(?:/[^\s\"'`]*)?)",
    re.IGNORECASE,
)

_SAFE_TLD = re.compile(
    r"\.(com|org|net|io|dev|app|cloud|co|us|uk|de|fr|nl|se|no|fi|dk|at|ch)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Registry URLs
# ---------------------------------------------------------------------------

_REGISTRY_URL_RE = re.compile(
    r"\b([\w.-]+(?:\.\w+)+/[\w./-]+(?::[\w.-]+)?)\b",
)

_AWS_ECR_RE = re.compile(
    r"\b(\d{12}\.dkr\.ecr\.[\w-]+\.amazonaws\.com/[\w./-]+(?::[\w.-]+)?)\b",
)

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b",
)

# ---------------------------------------------------------------------------
# API Keys / Tokens
# ---------------------------------------------------------------------------

_API_KEY_ASSIGNMENT_RE = re.compile(
    r"(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?key|"
    r"auth[_\-]?token|bearer)[\"'\s]*[=:][\"'\s]*([a-zA-Z0-9\-._/+]{20,})",
    re.IGNORECASE,
)

_AWS_ACCESS_KEY_RE = re.compile(
    r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b",
)

_GITHUB_TOKEN_RE = re.compile(
    r"\b(gh[psohr]_[a-zA-Z0-9]{36,})\b",
)

_GITLAB_TOKEN_RE = re.compile(
    r"\b(glpat-[a-zA-Z0-9\-_]{20,})\b",
)

# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

_PASSWORD_ASSIGNMENT_RE = re.compile(
    r"(?:password|passwd|pass|pwd|secret)[\"'\s]*[=:][\"'\s]*([^\s\"'`#]{4,})",
    re.IGNORECASE,
)

_CONNSTRING_PASSWORD_RE = re.compile(
    r"(?:postgres|postgresql|mysql|mongodb|redis)://[^:]+:([^@\s\"'`]{4,})@",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Private Keys
# ---------------------------------------------------------------------------

_PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
)

# ---------------------------------------------------------------------------
# AWS Resources
# ---------------------------------------------------------------------------

_ARN_RE = re.compile(
    r"\b(arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s\"'`]+)\b",
    re.IGNORECASE,
)

_S3_URI_RE = re.compile(
    r"\b(s3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](?:/[^\s\"'`]*)?)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Internal Hostnames
# ---------------------------------------------------------------------------

_INTERNAL_HOSTNAME_RE = re.compile(
    r"\b([a-zA-Z][a-zA-Z0-9\-]+-(?:prod|staging|dev|test|qa|uat)-\d+)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Git Remotes
# ---------------------------------------------------------------------------

_GIT_SSH_REMOTE_RE = re.compile(
    r"\bgit@([\w.-]+):([\w./-]+\.git)\b",
)

_GIT_HTTPS_REMOTE_RE = re.compile(
    r"\b(https://[\w.-]+/[\w./-]+\.git)\b",
)

# ---------------------------------------------------------------------------
# Compiled pattern definitions (ordered: more specific first)
# ---------------------------------------------------------------------------

BUILTIN_PATTERNS: list[PatternDef] = [
    # AWS ECR (before generic registry)
    PatternDef(
        name="aws_ecr",
        category=Category.AWS_RESOURCE,
        pattern=_AWS_ECR_RE,
    ),
    # ARN
    PatternDef(
        name="aws_arn",
        category=Category.AWS_RESOURCE,
        pattern=_ARN_RE,
    ),
    # S3 URIs
    PatternDef(
        name="aws_s3",
        category=Category.AWS_RESOURCE,
        pattern=_S3_URI_RE,
    ),
    # AWS access keys
    PatternDef(
        name="aws_access_key",
        category=Category.API_KEY,
        pattern=_AWS_ACCESS_KEY_RE,
    ),
    # GitHub tokens
    PatternDef(
        name="github_token",
        category=Category.API_KEY,
        pattern=_GITHUB_TOKEN_RE,
    ),
    # GitLab tokens
    PatternDef(
        name="gitlab_token",
        category=Category.API_KEY,
        pattern=_GITLAB_TOKEN_RE,
    ),
    # API key assignments
    PatternDef(
        name="api_key_assignment",
        category=Category.API_KEY,
        pattern=_API_KEY_ASSIGNMENT_RE,
        extract=lambda m: m.group(1),
    ),
    # Password assignments
    PatternDef(
        name="password_assignment",
        category=Category.PASSWORD,
        pattern=_PASSWORD_ASSIGNMENT_RE,
        extract=lambda m: m.group(1),
    ),
    # Connection string passwords
    PatternDef(
        name="connstring_password",
        category=Category.PASSWORD,
        pattern=_CONNSTRING_PASSWORD_RE,
        extract=lambda m: m.group(1),
    ),
    # Private key headers
    PatternDef(
        name="private_key_header",
        category=Category.PRIVATE_KEY,
        pattern=_PRIVATE_KEY_HEADER_RE,
    ),
    # Internal hostnames
    PatternDef(
        name="internal_hostname",
        category=Category.INTERNAL_HOSTNAME,
        pattern=_INTERNAL_HOSTNAME_RE,
    ),
    # Internal domains
    PatternDef(
        name="internal_domain",
        category=Category.DOMAIN,
        pattern=_INTERNAL_DOMAIN_RE,
    ),
    # Email addresses (before domain)
    PatternDef(
        name="email",
        category=Category.EMAIL,
        pattern=_EMAIL_RE,
    ),
    # Git SSH remotes
    PatternDef(
        name="git_ssh_remote",
        category=Category.GIT_REMOTE,
        pattern=_GIT_SSH_REMOTE_RE,
    ),
    # Git HTTPS remotes
    PatternDef(
        name="git_https_remote",
        category=Category.GIT_REMOTE,
        pattern=_GIT_HTTPS_REMOTE_RE,
    ),
    # Private IP addresses (before public)
    PatternDef(
        name="private_ip",
        category=Category.IP_ADDRESS,
        pattern=_PRIVATE_IP_RE,
    ),
    # Public IP addresses
    PatternDef(
        name="public_ip",
        category=Category.IP_ADDRESS,
        pattern=_PUBLIC_IP_RE,
    ),
]


def is_allowlisted(value: str) -> bool:
    """Return True if *value* should never be anonymized."""
    v = value.lower().strip()
    if v in {a.lower() for a in ALLOWLIST}:
        return True
    for prefix in ALLOWLIST_PREFIXES:
        if v.startswith(prefix):
            return True
    return False


def is_public_registry(value: str) -> bool:
    """Return True if *value* starts with a known public registry."""
    v = value.lower()
    return any(v.startswith(reg) or v == reg for reg in PUBLIC_REGISTRIES)


def is_public_git_host(host: str) -> bool:
    """Return True if *host* is a known public git host."""
    return host.lower() in PUBLIC_GIT_HOSTS
