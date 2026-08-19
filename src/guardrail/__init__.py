"""An LLM guardrail proxy, and the measurements that decide whether a guardrail is worth having.

Four questions this answers that a guardrail usually does not:

1. On a streaming response, how much of a detected secret reached the client before the cut?
You cannot un-send a byte, so the answer is never zero unless you gave up streaming.
2. At this route's attack prevalence, how often is a firing detector right? Precision depends on
prevalence far more than on the detector.
3. What happens when the guardrail itself fails, and what does an attacker gain by causing that?
4. Which evasions survive canonicalisation? The ones that do are published rather than removed.
"""

from __future__ import annotations

from .budget import Spend, availability, spend
from .detect import Finding, run_detector, shannon
from .errors import GuardrailError, GuardrailUnavailable, PolicyError, StreamError
from .evaluate import Rates, justify, rates, sweep
from .normalise import Normalised, canonical
from .policy import Policy
from .policy import load as load_policy
from .proxy import Transaction, client_sees, handle, posture
from .stream import Enforcement, buffered, enforce
from .upstream import SYSTEM_PROMPT, Completion, Upstream, completion
from .version import __version__

__all__ = [
    "SYSTEM_PROMPT",
    "Completion",
    "Enforcement",
    "Finding",
    "GuardrailError",
    "GuardrailUnavailable",
    "Normalised",
    "Policy",
    "PolicyError",
    "Rates",
    "Spend",
    "StreamError",
    "Transaction",
    "Upstream",
    "__version__",
    "availability",
    "buffered",
    "canonical",
    "client_sees",
    "completion",
    "enforce",
    "handle",
    "justify",
    "load_policy",
    "posture",
    "rates",
    "run_detector",
    "shannon",
    "spend",
    "sweep",
]
