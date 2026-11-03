"""v0.8 S: policy templates - drift-proof (validate + lint + selftest per template)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "policies" / "templates"


def _run(*args: str) -> tuple[int, str]:
    r = subprocess.run([sys.executable, "-m", "agentgate", *args],
                       capture_output=True, text=True, shell=False)
    return r.returncode, r.stdout + r.stderr


def test_templates_exist():
    assert sorted(p.name for p in TEMPLATES.glob("*.yaml")) == [
        "ci-unattended.yaml", "full-trust.yaml", "readonly-sandbox.yaml"]


def test_all_templates_validate_and_selftest():
    agents = {"readonly-sandbox.yaml": "claude-code",
              "full-trust.yaml": "claude-code",
              "ci-unattended.yaml": "ci-bot"}
    for t in sorted(TEMPLATES.glob("*.yaml")):
        rc, out = _run("validate", "--config", str(t))
        assert rc == 0, f"{t.name} validate failed:\n{out}"
        agent = agents[t.name]
        rc, out = _run("check", "--config", str(t), "--agent", agent, "--selftest")
        assert rc == 0, f"{t.name} selftest failed:\n{out}"


def test_readonly_and_ci_pass_lint():
    for name in ("readonly-sandbox.yaml", "ci-unattended.yaml"):
        rc, out = _run("lint", "--config", str(TEMPLATES / name))
        assert rc == 0, f"{name} lint failed:\n{out}"


def test_full_trust_intentionally_fails_lint():
    """full-trust is documented as unsafe; lint MUST flag its blanket allow."""
    rc, out = _run("lint", "--config", str(TEMPLATES / "full-trust.yaml"))
    assert rc == 1 and "blanket allow" in out
