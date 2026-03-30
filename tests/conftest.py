"""Shared pytest fixtures for codewash tests."""

import os
import shutil
from pathlib import Path

import pytest

TESTDATA_DIR = Path(__file__).parent / "testdata"


@pytest.fixture
def testdata_dir() -> Path:
    """Return the path to the testdata directory."""
    return TESTDATA_DIR


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """Create a temporary copy of testdata for write tests."""
    dest = tmp_path / "repo"
    shutil.copytree(TESTDATA_DIR, dest)
    return dest


@pytest.fixture
def tmp_output(tmp_path: Path) -> Path:
    """Return a path for output that does not exist yet."""
    return tmp_path / "output"
