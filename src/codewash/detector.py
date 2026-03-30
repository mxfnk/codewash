"""Module 2 – Detector: find sensitive values in file content."""

from __future__ import annotations

import re
from pathlib import Path

from codewash.config import CodewashConfig
from codewash.models import Category, Finding
from codewash.patterns import (
    BUILTIN_PATTERNS,
    PatternDef,
    _PRIVATE_KEY_HEADER_RE,
    _VERSION_CONTEXT_RE,
    is_allowlisted,
    is_public_git_host,
    is_public_registry,
)

# ---------------------------------------------------------------------------
# Comment line detection (for scan_comments = False)
# ---------------------------------------------------------------------------

_COMMENT_LINE_RE = re.compile(r"^\s*(?:#|//|;|--)")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_file(
    path: Path,
    config: CodewashConfig | None = None,
) -> list[Finding]:
    """Scan *path* line by line and return all findings.

    Returns an empty list for unreadable files (logs nothing – caller handles).
    """
    if config is None:
        config = CodewashConfig()

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    return detect_text(content, config=config)


def detect_text(
    content: str,
    config: CodewashConfig | None = None,
) -> list[Finding]:
    """Scan *content* string and return all findings (used directly in tests)."""
    if config is None:
        config = CodewashConfig()

    all_patterns = list(BUILTIN_PATTERNS)

    # Add custom patterns from config
    for cp in config.additional_patterns:
        all_patterns.append(
            PatternDef(
                name=cp.name,
                category=Category.CUSTOM,
                pattern=cp.pattern,
            )
        )

    lines = content.splitlines()
    findings: list[Finding] = []
    # Track which (line, col, len) spans are already claimed so we don't double-report
    claimed_spans: set[tuple[int, int, int]] = set()

    # Phase 1: multi-line private key blocks
    _detect_private_key_blocks(lines, findings, claimed_spans, config)

    # Phase 2: line-by-line patterns
    for lineno, line in enumerate(lines, start=1):
        # Respect scan_comments setting
        if not config.scan_comments and _COMMENT_LINE_RE.match(line):
            continue

        # Denylist: force-flag lines containing denylist terms
        for term in config.denylist:
            idx = line.find(term)
            while idx != -1:
                span = (lineno, idx, len(term))
                if span not in claimed_spans:
                    claimed_spans.add(span)
                    findings.append(
                        Finding(
                            category=Category.CUSTOM,
                            line=lineno,
                            column=idx,
                            matched_text=term,
                            replace_value=term,
                        )
                    )
                idx = line.find(term, idx + 1)

        for pdef in all_patterns:
            if pdef.category == Category.PRIVATE_KEY:
                continue  # handled above

            for match in pdef.pattern.finditer(line):
                # Determine the value to replace
                if pdef.extract is not None:
                    try:
                        replace_value = pdef.extract(match)
                    except (IndexError, AttributeError):
                        replace_value = match.group(0)
                elif match.lastindex and match.lastindex >= 1:
                    replace_value = match.group(1)
                else:
                    replace_value = match.group(0)

                if not replace_value:
                    continue

                # Allowlist check
                if is_allowlisted(replace_value):
                    continue

                # Config allowlist
                if any(a.lower() in replace_value.lower() for a in config.allowlist):
                    continue

                # Category-specific filtering
                if not _passes_category_filter(pdef, match, replace_value, line):
                    continue

                col = line.find(replace_value, match.start())
                span_key = (lineno, col, len(replace_value))
                if span_key in claimed_spans:
                    continue
                claimed_spans.add(span_key)

                findings.append(
                    Finding(
                        category=pdef.category,
                        line=lineno,
                        column=col,
                        matched_text=match.group(0),
                        replace_value=replace_value,
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Private key block detection (multi-line)
# ---------------------------------------------------------------------------


def _detect_private_key_blocks(
    lines: list[str],
    findings: list[Finding],
    claimed_spans: set[tuple[int, int, int]],
    config: CodewashConfig,
) -> None:
    """Detect -----BEGIN ... PRIVATE KEY----- blocks and add a single Finding."""
    in_block = False
    block_start_line = 0
    block_lines: list[str] = []

    for lineno, line in enumerate(lines, start=1):
        if not in_block:
            if _PRIVATE_KEY_HEADER_RE.search(line):
                in_block = True
                block_start_line = lineno
                block_lines = [line]
        else:
            block_lines.append(line)
            if "-----END" in line and "PRIVATE KEY-----" in line:
                full_block = "\n".join(block_lines)
                span_key = (block_start_line, 0, len(block_lines[0]))
                if span_key not in claimed_spans:
                    claimed_spans.add(span_key)
                    findings.append(
                        Finding(
                            category=Category.PRIVATE_KEY,
                            line=block_start_line,
                            column=0,
                            matched_text=full_block,
                            replace_value=full_block,
                        )
                    )
                in_block = False
                block_lines = []

    # Unterminated block (file ends inside a key)
    if in_block and block_lines:
        full_block = "\n".join(block_lines)
        span_key = (block_start_line, 0, len(block_lines[0]))
        if span_key not in claimed_spans:
            claimed_spans.add(span_key)
            findings.append(
                Finding(
                    category=Category.PRIVATE_KEY,
                    line=block_start_line,
                    column=0,
                    matched_text=full_block,
                    replace_value=full_block,
                )
            )


# ---------------------------------------------------------------------------
# Category-specific post-match filters
# ---------------------------------------------------------------------------


def _passes_category_filter(
    pdef: PatternDef,
    match: re.Match,
    replace_value: str,
    line: str,
) -> bool:
    """Return False if this match should be suppressed for category-specific reasons."""

    cat = pdef.category

    # IP addresses: suppress version number lookalikes
    if cat == Category.IP_ADDRESS:
        # If there's a version-context match overlapping this position, skip
        if _VERSION_CONTEXT_RE.search(line):
            ctx_match = _VERSION_CONTEXT_RE.search(line)
            if ctx_match and replace_value in ctx_match.group(0):
                return False
        # Loopback / unspecified are in allowlist, but double-check
        if replace_value.split("/")[0] in ("127.0.0.1", "0.0.0.0", "::1"):
            return False

    # Registry URLs: skip public registries
    if cat == Category.REGISTRY_URL:
        if is_public_registry(replace_value):
            return False

    # Email: skip noreply and example.com addresses
    if cat == Category.EMAIL:
        lower = replace_value.lower()
        if lower.startswith("noreply@") or lower.startswith("no-reply@"):
            return False
        if lower.endswith("@example.com"):
            return False

    # Git remotes: skip public hosts
    if cat == Category.GIT_REMOTE:
        if pdef.name == "git_ssh_remote":
            host = match.group(1)
            if is_public_git_host(host):
                return False
        elif pdef.name == "git_https_remote":
            url = replace_value
            for pub in ("github.com", "gitlab.com", "bitbucket.org"):
                if pub in url:
                    return False

    return True
