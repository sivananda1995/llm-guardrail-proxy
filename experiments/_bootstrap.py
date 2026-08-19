"""Put the repository root on the path so an experiment can import `attacks` and `guardrail`.

Experiments are scripts run from the repository root rather than an installed package, and
`attacks/` is deliberately outside the package: a corpus of attack strings is fixture, not library,
and does not belong in a wheel somebody's service imports. One import here beats five copies of
the same `sys.path` line.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
