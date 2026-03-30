"""Configuration loading and management for codewash."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from codewash.models import Category

CONFIG_FILENAME = ".codewash.yaml"


@dataclass
class CustomPattern:
    """A user-defined detection pattern from the config file."""

    name: str
    pattern: re.Pattern
    replacement_template: str  # e.g. "PROJECT-{n}"
    category: Category = Category.CUSTOM


@dataclass
class CodewashConfig:
    """Runtime configuration for a codewash run."""

    additional_patterns: list[CustomPattern] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    extra_extensions: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    scan_comments: bool = False


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = CodewashConfig()


def load_config(path: Path | None = None, source_dir: Path | None = None) -> CodewashConfig:
    """Load config from *path* or auto-discover in *source_dir*.

    Returns a ``CodewashConfig`` with defaults for any missing fields.
    Raises ``SystemExit`` on YAML parse errors or invalid patterns.
    """
    cfg_path: Path | None = path

    if cfg_path is None and source_dir is not None:
        candidate = source_dir / CONFIG_FILENAME
        if candidate.exists():
            cfg_path = candidate

    if cfg_path is None:
        return CodewashConfig()

    try:
        raw_text = cfg_path.read_text(encoding="utf-8")
    except OSError as exc:
        _fatal(f"Cannot read config file {cfg_path}: {exc}")

    try:
        data: dict[str, Any] = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        _fatal(f"Invalid YAML in config file {cfg_path}:\n{exc}", exit_code=1)

    if not isinstance(data, dict):
        _fatal(f"Config file {cfg_path} must be a YAML mapping at the top level.")

    return _parse_config(data, cfg_path)


def _parse_config(data: dict[str, Any], cfg_path: Path) -> CodewashConfig:
    cfg = CodewashConfig()

    # additional_patterns
    for entry in data.get("additional_patterns", []):
        name = entry.get("name", "<unnamed>")
        raw_pattern = entry.get("pattern", "")
        replacement = entry.get("replacement", f"{name.upper()}-{{n}}")
        try:
            compiled = re.compile(raw_pattern)
        except re.error as exc:
            _fatal(
                f"Invalid regex pattern '{name}' in {cfg_path}: {exc}",
                exit_code=1,
            )
        cfg.additional_patterns.append(
            CustomPattern(
                name=name,
                pattern=compiled,
                replacement_template=replacement,
            )
        )

    cfg.allowlist = [str(v) for v in data.get("allowlist", [])]
    cfg.denylist = [str(v) for v in data.get("denylist", [])]
    cfg.extra_extensions = [str(v).lstrip(".") for v in data.get("extra_extensions", [])]
    cfg.exclude_paths = [str(v) for v in data.get("exclude_paths", [])]
    cfg.scan_comments = bool(data.get("scan_comments", False))

    return cfg


def write_default_config(target: Path) -> None:
    """Write an annotated default .codewash.yaml to *target*."""
    content = """\
# codewash configuration
# See https://github.com/your-org/codewash for full documentation

# Additional regex patterns to detect (on top of built-in rules)
additional_patterns: []
#   - name: "jira-keys"
#     pattern: "(?:MYPROJ|DEVOPS|INFRA)-\\\\d+"
#     replacement: "PROJECT-{n}"

# Values that should NEVER be anonymized (added to built-in allowlist)
allowlist: []
#   - "api.stripe.com"
#   - "hooks.slack.com"

# Values that should ALWAYS be anonymized (even without a pattern match)
denylist: []
#   - "mycompany"
#   - "geheimes-projekt"

# Additional file extensions to scan (without the leading dot)
extra_extensions: []
#   - "j2"
#   - "tpl"

# Glob patterns for paths to skip
exclude_paths: []
#   - "test/**"
#   - "fixtures/**"
#   - "*.test.*"

# Whether to also scan comment lines (lines starting with # or //)
scan_comments: false
"""
    target.write_text(content, encoding="utf-8")


def _fatal(msg: str, exit_code: int = 1) -> None:
    from rich.console import Console

    Console(stderr=True).print(f"[red]Error:[/red] {msg}")
    sys.exit(exit_code)
