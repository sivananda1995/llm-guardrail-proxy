"""Fixtures. Everything is offline, deterministic, and built from the shipped policy.

There is no fixture that fabricates rates or findings. Every test that needs a measurement runs the
real detector over real text, because a test suite whose inputs are hand-written dictionaries tests
the shape of a dataclass and not the behaviour of a guardrail.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for entry in (ROOT, ROOT / "src"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from guardrail import policy as policy_module  # noqa: E402
from guardrail import upstream as upstream_module  # noqa: E402

POLICY_PATH = ROOT / "policies" / "support-assistant.yaml"


@pytest.fixture(scope="session")
def policy_path() -> Path:
    return POLICY_PATH


@pytest.fixture
def policy():
    """The shipped policy, from disk. Not a hand-built object: the loader is under test too."""
    return policy_module.load(POLICY_PATH)


@pytest.fixture
def source():
    return upstream_module.Upstream()


@pytest.fixture
def system_prompt() -> str:
    return upstream_module.SYSTEM_PROMPT


@pytest.fixture
def write_policy(tmp_path):
    """Write a policy variant to disk and load it, so loader failures are exercised as files."""
    def _write(payload: str):
        path = tmp_path / "policy.yaml"
        path.write_text(payload)
        return policy_module.load(path)
    return _write


@pytest.fixture
def base_policy_text(policy_path) -> str:
    return policy_path.read_text()
