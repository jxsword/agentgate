"""Shared fixtures for agentgate tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """Per-test workspace: policy.yaml + state dir + demo sandbox live here."""
    return tmp_path
