"""Module 1 – Scanner: discover relevant files in a directory tree."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from codewash.config import CodewashConfig

# ---------------------------------------------------------------------------
# Built-in lists
# ---------------------------------------------------------------------------

RELEVANT_EXTENSIONS: frozenset[str] = frozenset(
    [
        "yml", "yaml", "sh", "bash", "py", "rb", "toml", "ini",
        "cfg", "conf", "tf", "hcl", "json", "env", "properties",
    ]
)

# Exact file names (without extension) that are always included
RELEVANT_NAMES: frozenset[str] = frozenset(
    [
        "Dockerfile", "docker-compose", "Makefile", "Vagrantfile",
        ".env", ".gitlab-ci", "Jenkinsfile", "skaffold", "kustomization",
    ]
)

SKIP_DIRS: frozenset[str] = frozenset(
    [
        ".git", "node_modules", "target", "__pycache__",
        ".venv", "venv", ".terraform", "vendor",
        ".tox", ".mypy_cache", ".ruff_cache",
    ]
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(root: Path, config: CodewashConfig | None = None) -> list[Path]:
    """Return a sorted list of relevant file paths under *root*.

    - Symlinks are never followed.
    - Directories in ``SKIP_DIRS`` (and configured ``exclude_paths``) are skipped.
    - Only files with recognised extensions or names are returned.
    - Binary files are excluded based on a quick sniff check.
    """
    if config is None:
        config = CodewashConfig()

    extra_exts = frozenset(config.extra_extensions)
    effective_extensions = RELEVANT_EXTENSIONS | extra_exts

    results: list[Path] = []
    _walk(root, root, effective_extensions, config.exclude_paths, results)
    results.sort()
    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _walk(
    root: Path,
    current: Path,
    extensions: frozenset[str],
    exclude_globs: list[str],
    results: list[Path],
) -> None:
    """Recursively walk *current* and collect relevant files into *results*."""
    try:
        entries = list(current.iterdir())
    except PermissionError:
        return  # silently skip unreadable dirs

    for entry in entries:
        # Never follow symlinks
        if entry.is_symlink():
            continue

        if entry.is_dir():
            if entry.name in SKIP_DIRS:
                continue
            rel = entry.relative_to(root).as_posix()
            if _matches_any_glob(rel, exclude_globs):
                continue
            _walk(root, entry, extensions, exclude_globs, results)

        elif entry.is_file():
            rel = entry.relative_to(root).as_posix()
            if _matches_any_glob(rel, exclude_globs):
                continue
            if _is_relevant(entry, extensions) and not _is_binary(entry):
                results.append(entry)


def _is_relevant(path: Path, extensions: frozenset[str]) -> bool:
    """Return True if *path* should be scanned."""
    # Check extension
    suffix = path.suffix.lstrip(".")
    if suffix and suffix.lower() in extensions:
        return True
    # Check exact stem name (e.g. "Dockerfile", ".env", ".gitlab-ci")
    stem = path.stem  # name without last suffix
    name = path.name  # full name
    for candidate in (name, stem):
        if candidate in RELEVANT_NAMES:
            return True
    return False


def _is_binary(path: Path, sample_size: int = 8192) -> bool:
    """Heuristic: return True if the file looks like a binary."""
    try:
        with path.open("rb") as fh:
            chunk = fh.read(sample_size)
        # Files with a null byte are treated as binary
        return b"\x00" in chunk
    except OSError:
        return True  # treat unreadable files as binary (skip them)


def _matches_any_glob(rel_path: str, globs: list[str]) -> bool:
    """Return True if *rel_path* matches any of the glob patterns."""
    for glob in globs:
        if fnmatch.fnmatch(rel_path, glob):
            return True
        # Also match against just the filename for patterns like "*.test.*"
        filename = rel_path.rsplit("/", 1)[-1]
        if fnmatch.fnmatch(filename, glob):
            return True
    return False
