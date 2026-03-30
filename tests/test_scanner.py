"""Tests for codewash.scanner module."""

import os
from pathlib import Path

import pytest

from codewash.config import CodewashConfig
from codewash.scanner import scan, RELEVANT_EXTENSIONS, SKIP_DIRS, _is_relevant, _is_binary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_files(tmp_path: Path, names: list[str]) -> list[Path]:
    """Create empty files in tmp_path and return their paths."""
    created = []
    for name in names:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("content", encoding="utf-8")
        created.append(p)
    return created


# ---------------------------------------------------------------------------
# Extension recognition
# ---------------------------------------------------------------------------

class TestIsRelevant:
    def test_yaml_extension(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_yml_extension(self, tmp_path):
        p = tmp_path / "ci.yml"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_sh_extension(self, tmp_path):
        p = tmp_path / "deploy.sh"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_py_extension(self, tmp_path):
        p = tmp_path / "main.py"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_tf_extension(self, tmp_path):
        p = tmp_path / "main.tf"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_json_extension(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_toml_extension(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_dockerfile_name(self, tmp_path):
        p = tmp_path / "Dockerfile"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_dotenv_name(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_gitlab_ci_name(self, tmp_path):
        p = tmp_path / ".gitlab-ci.yml"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)  # .yml extension covers it

    def test_makefile_name(self, tmp_path):
        p = tmp_path / "Makefile"
        p.write_text("")
        assert _is_relevant(p, RELEVANT_EXTENSIONS)

    # Files that should NOT be relevant
    def test_png_not_relevant(self, tmp_path):
        p = tmp_path / "logo.png"
        p.write_text("")
        assert not _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_jpg_not_relevant(self, tmp_path):
        p = tmp_path / "photo.jpg"
        p.write_text("")
        assert not _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_md_not_relevant(self, tmp_path):
        p = tmp_path / "README.md"
        p.write_text("")
        assert not _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_js_not_relevant(self, tmp_path):
        p = tmp_path / "app.js"
        p.write_text("")
        assert not _is_relevant(p, RELEVANT_EXTENSIONS)

    def test_ts_not_relevant(self, tmp_path):
        p = tmp_path / "index.ts"
        p.write_text("")
        assert not _is_relevant(p, RELEVANT_EXTENSIONS)


# ---------------------------------------------------------------------------
# Skip directories
# ---------------------------------------------------------------------------

class TestSkipDirs:
    def test_skips_git(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]")
        result = scan(tmp_path)
        assert not any(".git" in str(p) for p in result)

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "package.json").write_text("{}")
        result = scan(tmp_path)
        assert not any("node_modules" in str(p) for p in result)

    def test_skips_pycache(self, tmp_path):
        pc = tmp_path / "__pycache__"
        pc.mkdir()
        (pc / "main.pyc").write_bytes(b"\x00test")
        # Also add a relevant file outside
        (tmp_path / "main.py").write_text("x=1")
        result = scan(tmp_path)
        assert not any("__pycache__" in str(p) for p in result)
        assert any("main.py" in str(p) for p in result)

    def test_skips_venv(self, tmp_path):
        venv = tmp_path / ".venv"
        venv.mkdir()
        (venv / "activate").write_text("# venv")
        result = scan(tmp_path)
        assert not any(".venv" in str(p) for p in result)

    def test_skips_terraform(self, tmp_path):
        tf = tmp_path / ".terraform"
        tf.mkdir()
        (tf / "main.tf").write_text("# terraform")
        result = scan(tmp_path)
        assert not any(".terraform" in str(p) for p in result)


# ---------------------------------------------------------------------------
# Symlink handling
# ---------------------------------------------------------------------------

class TestSymlinks:
    def test_does_not_follow_symlinks(self, tmp_path):
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        (real_dir / "secret.yaml").write_text("password: abc")

        symlink_dir = tmp_path / "symlinked"
        symlink_dir.symlink_to(real_dir)

        result = scan(tmp_path)
        # Should include real_dir/secret.yaml but NOT symlinked/secret.yaml
        rel_paths = [p.relative_to(tmp_path).as_posix() for p in result]
        assert any(s.startswith("real/") for s in rel_paths)
        assert not any(s.startswith("symlinked/") for s in rel_paths)


# ---------------------------------------------------------------------------
# Sort order
# ---------------------------------------------------------------------------

class TestSortOrder:
    def test_returns_sorted_paths(self, tmp_path):
        names = ["z.yaml", "a.yaml", "m.yaml", "b.sh"]
        make_files(tmp_path, names)
        result = scan(tmp_path)
        str_paths = [str(p) for p in result]
        assert str_paths == sorted(str_paths)


# ---------------------------------------------------------------------------
# Binary detection
# ---------------------------------------------------------------------------

class TestBinaryDetection:
    def test_skips_binary_file(self, tmp_path):
        binary = tmp_path / "data.yaml"
        binary.write_bytes(b"\x00\x01\x02binary")
        result = scan(tmp_path)
        assert binary not in result

    def test_includes_text_yaml(self, tmp_path):
        text = tmp_path / "config.yaml"
        text.write_text("key: value", encoding="utf-8")
        result = scan(tmp_path)
        assert text in result


# ---------------------------------------------------------------------------
# Extra extensions from config
# ---------------------------------------------------------------------------

class TestExtraExtensions:
    def test_extra_extension_included(self, tmp_path):
        cfg = CodewashConfig(extra_extensions=["j2"])
        template = tmp_path / "deploy.j2"
        template.write_text("server: {{ host }}")
        result = scan(tmp_path, config=cfg)
        assert template in result

    def test_unknown_extension_excluded_without_config(self, tmp_path):
        template = tmp_path / "deploy.j2"
        template.write_text("server: {{ host }}")
        result = scan(tmp_path)
        assert template not in result


# ---------------------------------------------------------------------------
# Exclude paths
# ---------------------------------------------------------------------------

class TestExcludePaths:
    def test_exclude_glob(self, tmp_path):
        cfg = CodewashConfig(exclude_paths=["test/**"])
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "fixture.yaml").write_text("host: 10.0.0.1")
        (tmp_path / "prod.yaml").write_text("host: 10.0.0.2")

        result = scan(tmp_path, config=cfg)
        paths_str = [p.name for p in result]
        assert "prod.yaml" in paths_str
        assert "fixture.yaml" not in paths_str


# ---------------------------------------------------------------------------
# Integration: testdata directory
# ---------------------------------------------------------------------------

class TestTestdata:
    def test_scans_testdata(self, testdata_dir):
        results = scan(testdata_dir)
        names = {p.name for p in results}
        assert ".gitlab-ci.yml" in names
        assert "deployment.yaml" in names
        assert "deploy.sh" in names

    def test_no_skip_dir_entries(self, testdata_dir):
        results = scan(testdata_dir)
        for p in results:
            for skip in SKIP_DIRS:
                assert skip not in p.parts, f"Skipped dir '{skip}' found in result: {p}"
