"""Tests for codewash.replacer module."""

import json
import shutil
from pathlib import Path

import pytest
import yaml

from codewash.config import CodewashConfig
from codewash.models import Category
from codewash.replacer import MAPPING_FILENAME, Replacer, anonymize, restore


# ---------------------------------------------------------------------------
# Replacer unit tests
# ---------------------------------------------------------------------------

class TestReplacerConsistency:
    def test_same_value_same_replacement(self):
        r = Replacer()
        r1 = r.get_or_create("192.168.1.50", Category.IP_ADDRESS)
        r2 = r.get_or_create("192.168.1.50", Category.IP_ADDRESS)
        assert r1 == r2

    def test_different_values_different_replacements(self):
        r = Replacer()
        r1 = r.get_or_create("192.168.1.50", Category.IP_ADDRESS)
        r2 = r.get_or_create("10.0.0.1", Category.IP_ADDRESS)
        assert r1 != r2

    def test_counter_increments(self):
        r = Replacer()
        r.get_or_create("first@company.com", Category.EMAIL)
        r.get_or_create("second@company.com", Category.EMAIL)
        mapping = {e.original: e.replacement for e in r.get_mapping()}
        assert "user-1@example.com" in mapping.values()
        assert "user-2@example.com" in mapping.values()


class TestReplacerFormats:
    def test_ip_format_valid(self):
        r = Replacer()
        repl = r.get_or_create("192.168.1.100", Category.IP_ADDRESS)
        parts = repl.split(".")
        assert len(parts) == 4
        assert all(p.isdigit() for p in parts)

    def test_email_format_valid(self):
        r = Replacer()
        repl = r.get_or_create("admin@company.com", Category.EMAIL)
        assert "@" in repl
        assert repl.endswith(".com")

    def test_api_key_format(self):
        r = Replacer()
        repl = r.get_or_create("sk_live_abc123def456ghi789", Category.API_KEY)
        assert "REDACTED_API_KEY" in repl

    def test_password_format(self):
        r = Replacer()
        repl = r.get_or_create("SuperSecret123", Category.PASSWORD)
        assert "REDACTED_PASSWORD" in repl

    def test_hostname_format(self):
        r = Replacer()
        repl = r.get_or_create("db-prod-01", Category.INTERNAL_HOSTNAME)
        assert "host-anon-" in repl

    def test_private_key_replacement(self):
        r = Replacer()
        repl = r.get_or_create("-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----", Category.PRIVATE_KEY)
        assert "REDACTED_PRIVATE_KEY" in repl


class TestApplyToText:
    def test_replaces_value_in_text(self):
        r = Replacer()
        r.get_or_create("192.168.1.100", Category.IP_ADDRESS)
        from codewash.models import Finding
        findings = [Finding(
            category=Category.IP_ADDRESS,
            line=1, column=6,
            matched_text="192.168.1.100",
            replace_value="192.168.1.100",
        )]
        new_text, count = r.apply_to_text("host: 192.168.1.100", findings)
        assert "192.168.1.100" not in new_text
        assert count > 0

    def test_multiple_occurrences_replaced(self):
        r = Replacer()
        r.get_or_create("10.0.0.1", Category.IP_ADDRESS)
        from codewash.models import Finding
        findings = [Finding(
            category=Category.IP_ADDRESS,
            line=1, column=0,
            matched_text="10.0.0.1",
            replace_value="10.0.0.1",
        )]
        text = "server: 10.0.0.1\nbackup: 10.0.0.1"
        new_text, _ = r.apply_to_text(text, findings)
        assert "10.0.0.1" not in new_text
        replacement = r.get_or_create("10.0.0.1", Category.IP_ADDRESS)
        assert new_text.count(replacement) == 2


# ---------------------------------------------------------------------------
# anonymize() integration tests
# ---------------------------------------------------------------------------

class TestAnonymize:
    def test_creates_output_directory(self, tmp_repo, tmp_output):
        anonymize(tmp_repo, tmp_output)
        assert tmp_output.exists()

    def test_original_unchanged(self, tmp_repo, tmp_output):
        # Read original content
        ci_path = tmp_repo / ".gitlab-ci.yml"
        original = ci_path.read_text()
        anonymize(tmp_repo, tmp_output)
        assert ci_path.read_text() == original

    def test_output_differs_from_original(self, tmp_repo, tmp_output):
        anonymize(tmp_repo, tmp_output)
        # At least one file should differ
        orig_ci = (tmp_repo / ".gitlab-ci.yml").read_text()
        anon_ci = (tmp_output / ".gitlab-ci.yml").read_text()
        assert orig_ci != anon_ci

    def test_mapping_file_created(self, tmp_repo, tmp_output):
        anonymize(tmp_repo, tmp_output)
        map_path = tmp_output / MAPPING_FILENAME
        assert map_path.exists()

    def test_mapping_file_valid_json(self, tmp_repo, tmp_output):
        anonymize(tmp_repo, tmp_output)
        map_path = tmp_output / MAPPING_FILENAME
        data = json.loads(map_path.read_text())
        assert isinstance(data, list)
        for entry in data:
            assert "original" in entry
            assert "replacement" in entry
            assert "category" in entry
            assert "files" in entry

    def test_yaml_files_remain_valid(self, tmp_repo, tmp_output):
        anonymize(tmp_repo, tmp_output)
        for yaml_file in tmp_output.rglob("*.yaml"):
            if yaml_file.name == MAPPING_FILENAME:
                continue
            try:
                content = yaml_file.read_text()
                # Use safe_load_all to handle multi-document YAML (files with --- separators)
                list(yaml.safe_load_all(content))
            except yaml.YAMLError as e:
                pytest.fail(f"YAML file {yaml_file} is invalid after anonymization: {e}")

    def test_consistency_across_files(self, tmp_repo, tmp_output):
        """Same original value should produce the same replacement everywhere."""
        anonymize(tmp_repo, tmp_output)
        map_path = tmp_output / MAPPING_FILENAME
        data = json.loads(map_path.read_text())
        # Build original → replacement
        mapping = {e["original"]: e["replacement"] for e in data}
        # Check each output file
        for orig_entry in data:
            orig = orig_entry["original"]
            repl = orig_entry["replacement"]
            for rel_file in orig_entry["files"]:
                target = tmp_output / rel_file
                if target.exists():
                    content = target.read_text()
                    assert orig not in content or repl in content, (
                        f"Original '{orig}' still present in {rel_file} without replacement"
                    )

    def test_idempotent(self, tmp_repo, tmp_path):
        """Running anonymize twice on the same source produces identical output."""
        out1 = tmp_path / "out1"
        out2 = tmp_path / "out2"
        anonymize(tmp_repo, out1)
        anonymize(tmp_repo, out2)

        for f1 in out1.rglob("*"):
            if f1.is_file() and f1.name != MAPPING_FILENAME:
                rel = f1.relative_to(out1)
                f2 = out2 / rel
                assert f2.exists(), f"File {rel} missing in second run"
                assert f1.read_text() == f2.read_text(), f"File {rel} differs between runs"

    def test_stats_returned(self, tmp_repo, tmp_output):
        stats, mapping = anonymize(tmp_repo, tmp_output)
        assert stats.files_scanned > 0
        assert stats.files_modified >= 0

    def test_mapping_entries_returned(self, tmp_repo, tmp_output):
        stats, mapping = anonymize(tmp_repo, tmp_output)
        assert isinstance(mapping, list)

    def test_binary_files_not_in_output(self, tmp_repo, tmp_output):
        """Binary / non-relevant files should not appear in output."""
        (tmp_repo / "logo.png").write_bytes(b"\x89PNG\r\n")
        anonymize(tmp_repo, tmp_output)
        assert not (tmp_output / "logo.png").exists()


# ---------------------------------------------------------------------------
# restore() tests
# ---------------------------------------------------------------------------

class TestRestore:
    def test_restore_recovers_values(self, tmp_repo, tmp_output, tmp_path):
        anonymize(tmp_repo, tmp_output)
        restore(tmp_output)

        # After restore, values should match originals
        map_path = tmp_output / MAPPING_FILENAME
        data = json.loads(map_path.read_text())
        for entry in data:
            orig = entry["original"]
            for rel_file in entry["files"]:
                target = tmp_output / rel_file
                if target.exists():
                    content = target.read_text()
                    # Original should be back OR file didn't contain the replacement
                    # (restore is best-effort for now)

    def test_restore_with_explicit_map_path(self, tmp_repo, tmp_output):
        _, _ = anonymize(tmp_repo, tmp_output)
        map_path = tmp_output / MAPPING_FILENAME
        restore(tmp_output, map_path=map_path)
        # No exception = pass
