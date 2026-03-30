"""Data models for codewash."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Category(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    REGISTRY_URL = "registry_url"
    EMAIL = "email"
    API_KEY = "api_key"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    AWS_RESOURCE = "aws_resource"
    INTERNAL_HOSTNAME = "internal_hostname"
    GIT_REMOTE = "git_remote"
    CUSTOM = "custom"

    @property
    def label(self) -> str:
        """Short uppercase label for display."""
        return {
            Category.IP_ADDRESS: "IP",
            Category.DOMAIN: "DOMAIN",
            Category.REGISTRY_URL: "REGISTRY",
            Category.EMAIL: "EMAIL",
            Category.API_KEY: "API_KEY",
            Category.PASSWORD: "PASSWORD",
            Category.PRIVATE_KEY: "PRIVKEY",
            Category.AWS_RESOURCE: "AWS",
            Category.INTERNAL_HOSTNAME: "HOSTNAME",
            Category.GIT_REMOTE: "GIT",
            Category.CUSTOM: "CUSTOM",
        }[self]


@dataclass
class Finding:
    """A single sensitive finding in a file."""

    category: Category
    line: int           # 1-based line number
    column: int         # 0-based column
    matched_text: str   # The exact text that was matched
    replace_value: str  # The specific value that should be replaced (may equal matched_text)


@dataclass
class MappingEntry:
    """Maps an original value to its anonymized replacement."""

    original: str
    replacement: str
    category: str
    files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "replacement": self.replacement,
            "category": self.category,
            "files": sorted(self.files),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MappingEntry":
        return cls(
            original=data["original"],
            replacement=data["replacement"],
            category=data["category"],
            files=data.get("files", []),
        )


@dataclass
class Stats:
    """Aggregated statistics for a scan/anonymize run."""

    files_scanned: int = 0
    files_modified: int = 0
    replacements_made: int = 0
    findings_by_category: dict[str, int] = field(default_factory=dict)

    def increment(self, category: Category) -> None:
        key = category.value
        self.findings_by_category[key] = self.findings_by_category.get(key, 0) + 1

    @property
    def total_findings(self) -> int:
        return sum(self.findings_by_category.values())
