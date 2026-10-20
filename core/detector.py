"""Simulated signature-matching engine (a TEACHING MODEL, not a real product).

IMPORTANT — WHAT THIS MODULE IS
-------------------------------
This is a deliberately naive, self-contained detector used for classroom
demonstration only. It performs literal keyword and regular-expression
matching against the exact bytes of a string. That is precisely the weakness
being taught: real-world signature engines that only look at static patterns
are defeated by trivial encoding/obfuscation, which is why modern endpoint
protections use behavioural analysis, sandboxing, and heuristics instead.

This module is NOT an antivirus, NOT an EDR, and NOT a bypass toolkit for any
real security product. It never makes network calls and never touches files
outside ``signatures/*.json``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Default signature file shipped with the project.
DEFAULT_SIGNATURE_PATH = (
    Path(__file__).resolve().parent.parent / "signatures" / "default_signatures.json"
)

VALID_KINDS = ("keyword", "regex")


@dataclass(frozen=True)
class Signature:
    """A single detection rule loaded from JSON."""

    name: str
    kind: str  # "keyword" | "regex"
    pattern: str
    severity: str = "medium"

    def __post_init__(self) -> None:
        if self.kind not in VALID_KINDS:
            raise ValueError(f"signature '{self.name}': kind must be one of {VALID_KINDS}")
        if self.kind == "regex":
            re.compile(self.pattern)  # fail fast on bad patterns


@dataclass(frozen=True)
class Match:
    """A signature that fired during a scan."""

    signature: Signature
    matched_text: str


@dataclass
class ScanResult:
    """Outcome of scanning one string."""

    payload: str
    matches: list[Match] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return bool(self.matches)


class SignatureDetector:
    """Naive static pattern matcher over a list of :class:`Signature` rules."""

    def __init__(self, signatures: list[Signature]) -> None:
        self.signatures = signatures
        # Pre-compile regexes once for speed and clarity.
        self._regexes = {
            sig.name: re.compile(sig.pattern, re.IGNORECASE)
            for sig in signatures
            if sig.kind == "regex"
        }
        # Keywords are lower-cased for a case-insensitive literal match.
        self._keywords = {
            sig.name: (sig.pattern.lower(), sig)
            for sig in signatures
            if sig.kind == "keyword"
        }

    # -- loading -----------------------------------------------------------

    @classmethod
    def from_json(cls, path: str | Path | None = None) -> "SignatureDetector":
        """Load signatures from a JSON file (defaults to the shipped set)."""
        sig_path = Path(path) if path else DEFAULT_SIGNATURE_PATH
        raw = json.loads(sig_path.read_text(encoding="utf-8"))
        signatures = [Signature(**entry) for entry in raw]
        return cls(signatures)

    # -- scanning ----------------------------------------------------------

    def scan(self, payload: str) -> ScanResult:
        """Run every signature against ``payload`` and collect matches.

        This is intentionally a *static* check: no decoding, no emulation,
        no behavioural analysis — that is the whole point of the lesson.
        """
        result = ScanResult(payload=payload)
        haystack = payload.lower()

        # self._keywords maps signature name -> (lower-cased pattern, signature);
        # iterate the *values* so we match against the pattern, not the name.
        for text, signature in self._keywords.values():
            if text in haystack:
                idx = haystack.index(text)
                result.matches.append(Match(signature, payload[idx : idx + len(text)]))

        for name, regex in self._regexes.items():
            signature = next(s for s in self.signatures if s.name == name)
            match = regex.search(payload)
            if match:
                result.matches.append(Match(signature, match.group(0)))

        return result
