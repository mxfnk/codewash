"""Module 3 – Replacer: consistently replace sensitive values across a repository."""

from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path

from codewash.config import CodewashConfig
from codewash.detector import detect_file
from codewash.models import Category, Finding, MappingEntry, Stats
from codewash.scanner import scan

MAPPING_FILENAME = ".codewash-map.json"

# ---------------------------------------------------------------------------
# Replacement templates per category
# ---------------------------------------------------------------------------

_REPLACEMENT_TEMPLATES: dict[Category, str] = {
    Category.IP_ADDRESS: "198.51.100.{n}",
    Category.DOMAIN: "service-{n}.example.internal",
    Category.REGISTRY_URL: "registry.example.com/project-{n}/image",
    Category.EMAIL: "user-{n}@example.com",
    Category.API_KEY: "REDACTED_API_KEY_{n:04d}",
    Category.PASSWORD: "REDACTED_PASSWORD_{n:04d}",
    Category.PRIVATE_KEY: "# REDACTED_PRIVATE_KEY",
    Category.AWS_RESOURCE: "arn:aws:s3:::example-bucket-{n}",
    Category.INTERNAL_HOSTNAME: "host-anon-{n:02d}",
    Category.GIT_REMOTE: "git@git.example.com:org/repo-{n}.git",
    Category.CUSTOM: "REDACTED_CUSTOM_{n:04d}",
}


class Replacer:
    """Manages the global mapping of original → replacement values."""

    def __init__(self) -> None:
        # original_value -> MappingEntry
        self._map: dict[str, MappingEntry] = {}
        # per-category counter
        self._counters: dict[Category, int] = defaultdict(int)
        # custom pattern counters (by pattern name / category combo)
        self._custom_counters: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_or_create(self, value: str, category: Category) -> str:
        """Return the anonymized replacement for *value*, creating one if needed."""
        if value in self._map:
            return self._map[value].replacement

        self._counters[category] += 1
        n = self._counters[category]
        replacement = self._generate_replacement(value, category, n)

        self._map[value] = MappingEntry(
            original=value,
            replacement=replacement,
            category=category.value,
        )
        return replacement

    def record_file(self, value: str, filepath: str) -> None:
        """Record that *value* was found in *filepath*."""
        if value in self._map:
            files = self._map[value].files
            if filepath not in files:
                files.append(filepath)

    def apply_to_text(self, content: str, findings: list[Finding]) -> tuple[str, int]:
        """Apply all *findings* replacements to *content*.

        Returns (new_content, replacements_count).
        Longer matches are replaced first to avoid substring conflicts.
        """
        replacements: list[tuple[str, str]] = []
        for f in findings:
            replacement = self.get_or_create(f.replace_value, f.category)
            replacements.append((f.replace_value, replacement))

        # Sort by length descending so longer strings are replaced first
        replacements.sort(key=lambda t: len(t[0]), reverse=True)

        result = content
        count = 0
        for original, replacement in replacements:
            if original in result:
                result = result.replace(original, replacement)
                count += result.count(replacement)  # approximate
        # More accurate: count actual replacements made
        count = sum(
            content.count(orig)
            for orig, _ in replacements
            if orig in content
        )
        return result, count

    def get_mapping(self) -> list[MappingEntry]:
        return list(self._map.values())

    def save_mapping(self, output_dir: Path) -> Path:
        """Serialize the mapping to JSON and save it to *output_dir*."""
        map_path = output_dir / MAPPING_FILENAME
        data = [entry.to_dict() for entry in self._map.values()]
        map_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return map_path

    # ------------------------------------------------------------------
    # Replacement generation
    # ------------------------------------------------------------------

    def _generate_replacement(self, original: str, category: Category, n: int) -> str:
        template = _REPLACEMENT_TEMPLATES.get(category, "REDACTED_{n:04d}")
        try:
            return template.format(n=n)
        except (KeyError, ValueError):
            return f"REDACTED_{n:04d}"


# ---------------------------------------------------------------------------
# High-level anonymize function
# ---------------------------------------------------------------------------


def anonymize(
    source: Path,
    output: Path,
    config: CodewashConfig | None = None,
    files: list[Path] | None = None,
) -> tuple[Stats, list[MappingEntry]]:
    """Anonymize *source* into *output*.

    Parameters
    ----------
    source:
        Root directory to anonymize.
    output:
        Destination directory (will be created; must not exist unless caller handles it).
    config:
        Optional configuration.
    files:
        Pre-computed list of relevant files (from scanner). If None, scanner runs.

    Returns
    -------
    (Stats, list[MappingEntry])
    """
    if config is None:
        config = CodewashConfig()

    if files is None:
        files = scan(source, config)

    replacer = Replacer()
    stats = Stats(files_scanned=len(files))

    # First pass: collect all findings and register replacements globally
    file_findings: dict[Path, list[Finding]] = {}
    for path in files:
        findings = detect_file(path, config=config)
        file_findings[path] = findings
        for f in findings:
            replacer.get_or_create(f.replace_value, f.category)
            stats.increment(f.category)
            rel = path.relative_to(source).as_posix()
            replacer.record_file(f.replace_value, rel)

    # Second pass: write files to output
    output.mkdir(parents=True, exist_ok=True)

    for path in files:
        rel = path.relative_to(source)
        dest = output / rel
        dest.parent.mkdir(parents=True, exist_ok=True)

        findings = file_findings[path]
        if not findings:
            shutil.copy2(path, dest)
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            shutil.copy2(path, dest)
            continue

        new_content, n_replaced = replacer.apply_to_text(content, findings)
        dest.write_text(new_content, encoding="utf-8")

        if new_content != content:
            stats.files_modified += 1
            stats.replacements_made += n_replaced

    replacer.save_mapping(output)

    return stats, replacer.get_mapping()


# ---------------------------------------------------------------------------
# Restore function
# ---------------------------------------------------------------------------


def restore(anon_dir: Path, map_path: Path | None = None) -> Stats:
    """Restore original values in *anon_dir* using the mapping file.

    Modifies files in-place.
    """
    if map_path is None:
        map_path = anon_dir / MAPPING_FILENAME

    data = json.loads(map_path.read_text(encoding="utf-8"))
    entries = [MappingEntry.from_dict(d) for d in data]

    # Build replacement → original lookup
    reverse_map: dict[str, str] = {e.replacement: e.original for e in entries}

    # Sort by length descending to avoid partial replacements
    sorted_pairs = sorted(reverse_map.items(), key=lambda t: len(t[0]), reverse=True)

    stats = Stats()
    for path in anon_dir.rglob("*"):
        if path.is_file() and path.name != MAPPING_FILENAME:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            new_content = content
            for replacement, original in sorted_pairs:
                if replacement in new_content:
                    new_content = new_content.replace(replacement, original)

            if new_content != content:
                path.write_text(new_content, encoding="utf-8")
                stats.files_modified += 1
                stats.files_scanned += 1
            else:
                stats.files_scanned += 1

    return stats
