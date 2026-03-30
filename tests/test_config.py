"""Tests for codewash.config module."""

import re
from pathlib import Path

import pytest

from codewash.config import (
    CodewashConfig,
    load_config,
    write_default_config,
    CONFIG_FILENAME,
)
from codewash.models import Category


# ---------------------------------------------------------------------------
# Default config
# ---------------------------------------------------------------------------

class TestDefaultConfig:
    def test_default_has_no_extra_extensions(self):
        cfg = CodewashConfig()
        assert cfg.extra_extensions == []

    def test_default_scan_comments_false(self):
        assert CodewashConfig().scan_comments is False

    def test_default_no_allowlist(self):
        assert CodewashConfig().allowlist == []

    def test_default_no_denylist(self):
        assert CodewashConfig().denylist == []

    def test_default_no_additional_patterns(self):
        assert CodewashConfig().additional_patterns == []

    def test_default_no_exclude_paths(self):
        assert CodewashConfig().exclude_paths == []


# ---------------------------------------------------------------------------
# load_config with valid files
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_load_returns_config(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text("allowlist:\n  - api.stripe.com\n")
        cfg = load_config(path=cfg_file)
        assert "api.stripe.com" in cfg.allowlist

    def test_load_denylist(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text("denylist:\n  - mycompany\n")
        cfg = load_config(path=cfg_file)
        assert "mycompany" in cfg.denylist

    def test_load_extra_extensions(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text("extra_extensions:\n  - j2\n  - tpl\n")
        cfg = load_config(path=cfg_file)
        assert "j2" in cfg.extra_extensions
        assert "tpl" in cfg.extra_extensions

    def test_load_exclude_paths(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text("exclude_paths:\n  - 'test/**'\n")
        cfg = load_config(path=cfg_file)
        assert "test/**" in cfg.exclude_paths

    def test_load_scan_comments_true(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text("scan_comments: true\n")
        cfg = load_config(path=cfg_file)
        assert cfg.scan_comments is True

    def test_load_additional_patterns(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text(
            "additional_patterns:\n"
            "  - name: jira-keys\n"
            "    pattern: 'INFRA-\\\\d+'\n"
            "    replacement: 'TICKET-{n}'\n"
        )
        cfg = load_config(path=cfg_file)
        assert len(cfg.additional_patterns) == 1
        assert cfg.additional_patterns[0].name == "jira-keys"
        assert isinstance(cfg.additional_patterns[0].pattern, re.Pattern)

    def test_missing_fields_get_defaults(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text("allowlist:\n  - example.com\n")
        cfg = load_config(path=cfg_file)
        # Fields not specified should have defaults
        assert cfg.scan_comments is False
        assert cfg.extra_extensions == []
        assert cfg.denylist == []

    def test_empty_file_returns_defaults(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text("")
        cfg = load_config(path=cfg_file)
        assert cfg == CodewashConfig()

    def test_none_path_no_config_file_returns_defaults(self):
        cfg = load_config(path=None, source_dir=None)
        assert cfg == CodewashConfig()


# ---------------------------------------------------------------------------
# Auto-discovery
# ---------------------------------------------------------------------------

class TestAutoDiscovery:
    def test_auto_discovers_config_in_source_dir(self, tmp_path):
        cfg_file = tmp_path / CONFIG_FILENAME
        cfg_file.write_text("allowlist:\n  - api.example.com\n")
        cfg = load_config(source_dir=tmp_path)
        assert "api.example.com" in cfg.allowlist

    def test_no_config_in_dir_returns_defaults(self, tmp_path):
        cfg = load_config(source_dir=tmp_path)
        assert cfg == CodewashConfig()

    def test_explicit_path_takes_precedence(self, tmp_path):
        # Two config files
        auto = tmp_path / CONFIG_FILENAME
        auto.write_text("allowlist:\n  - auto-value\n")
        explicit = tmp_path / "custom.yaml"
        explicit.write_text("allowlist:\n  - explicit-value\n")

        cfg = load_config(path=explicit, source_dir=tmp_path)
        assert "explicit-value" in cfg.allowlist
        assert "auto-value" not in cfg.allowlist


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_invalid_yaml_exits(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text("key: [unclosed bracket\n")
        with pytest.raises(SystemExit) as exc:
            load_config(path=cfg_file)
        assert exc.value.code == 1

    def test_invalid_regex_pattern_exits(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text(
            "additional_patterns:\n"
            "  - name: bad\n"
            "    pattern: '[invalid regex('\n"
        )
        with pytest.raises(SystemExit) as exc:
            load_config(path=cfg_file)
        assert exc.value.code == 1

    def test_extension_dot_stripped(self, tmp_path):
        cfg_file = tmp_path / ".codewash.yaml"
        cfg_file.write_text("extra_extensions:\n  - '.j2'\n")
        cfg = load_config(path=cfg_file)
        assert "j2" in cfg.extra_extensions
        assert ".j2" not in cfg.extra_extensions


# ---------------------------------------------------------------------------
# write_default_config
# ---------------------------------------------------------------------------

class TestWriteDefaultConfig:
    def test_creates_file(self, tmp_path):
        target = tmp_path / ".codewash.yaml"
        write_default_config(target)
        assert target.exists()

    def test_file_is_valid_yaml(self, tmp_path):
        import yaml
        target = tmp_path / ".codewash.yaml"
        write_default_config(target)
        data = yaml.safe_load(target.read_text())
        assert isinstance(data, dict)

    def test_file_has_expected_keys(self, tmp_path):
        import yaml
        target = tmp_path / ".codewash.yaml"
        write_default_config(target)
        data = yaml.safe_load(target.read_text())
        for key in ("additional_patterns", "allowlist", "denylist", "extra_extensions", "exclude_paths", "scan_comments"):
            assert key in data


# ---------------------------------------------------------------------------
# Integration: testdata config
# ---------------------------------------------------------------------------

class TestTestdataConfig:
    def test_loads_testdata_config(self, testdata_dir):
        cfg = load_config(source_dir=testdata_dir)
        assert "meinefirma" in cfg.denylist
        assert len(cfg.additional_patterns) > 0
        assert "j2" in cfg.extra_extensions
