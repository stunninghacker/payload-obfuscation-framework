"""Reversible string obfuscation transforms (lab/teaching use only).

Each obfuscator returns a *representation* of the original string that a
naive keyword/regex detector will not recognize, plus a matching
de-obfuscator that recovers the input exactly. Randomness is used only to
pick markers/separators that are guaranteed not to collide with the input,
so every transform stays roundtrip-safe.
"""

from __future__ import annotations

import random
from typing import Callable, Optional

# Candidate marker/separator characters (printable, unlikely in test data).
_MARKER_CANDIDATES = "~^#%&*=+:@$?;<>[]{}"


class ObfuscatorError(ValueError):
    """Raised when an obfuscation transform is applied incorrectly."""


def _pick_safe_char(data: str) -> str:
    """Return the first candidate character that does not appear in ``data``."""
    for candidate in _MARKER_CANDIDATES:
        if candidate not in data:
            return candidate
    # Ultra-rare fallback: scan the printable range for an unused character.
    for codepoint in range(0x1E, 0x7F):
        char = chr(codepoint)
        if char not in data:
            return char
    raise ObfuscatorError("could not find a safe marker character for input")


# --------------------------------------------------------------------------
# 1. Random character insertion (marker-tagged, so it is reversible)
# --------------------------------------------------------------------------


def random_char_insertion(data: str, key: Optional[str] = None) -> str:
    """Insert ``marker + random char`` after every character.

    The chosen marker never occurs in the input and is emitted as the first
    character of the result, so the de-obfuscator can strip insertions:
    whenever it sees ``marker``, it drops the marker *and* the following char.
    """
    marker = _pick_safe_char(data)
    rng = random.Random()  # entropy only affects the junk chars, not correctness
    junk = "abcdefghijklmnopqrstuvwxyz0123456789"
    body = "".join(c + marker + rng.choice(junk) for c in data)
    return marker + body


def random_char_removal(data: str, key: Optional[str] = None) -> str:
    """Inverse of :func:`random_char_insertion`."""
    if not data:
        return ""
    marker, body = data[0], data[1:]
    result: list[str] = []
    i = 0
    while i < len(body):
        char = body[i]
        if char == marker and i + 1 < len(body):
            i += 2  # skip marker + inserted junk character
            continue
        result.append(char)
        i += 1
    return "".join(result)


# --------------------------------------------------------------------------
# 2. Split and concat (chunked "rejoin" representation)
# --------------------------------------------------------------------------


def split_and_concat(data: str, key: Optional[str] = None) -> str:
    """Break the string into small chunks and join them with a safe separator.

    Result looks like ``w~h~o~a~m~i``. Because the keyword is no longer a
    contiguous run of characters, literal keyword matching misses it.
    """
    separator = _pick_safe_char(data)
    rng = random.Random()
    chunk_size = rng.randint(1, 3)
    chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
    return separator + separator.join(chunks)


def split_join_inverse(data: str, key: Optional[str] = None) -> str:
    """Inverse of :func:`split_and_concat`."""
    if not data:
        return ""
    separator, body = data[0], data[1:]
    return "".join(body.split(separator)) if body else ""


# --------------------------------------------------------------------------
# 3. Simple reversal
# --------------------------------------------------------------------------


def reverse_transform(data: str, key: Optional[str] = None) -> str:
    """Reverse the string ("whoami" -> "imahow")."""
    return data[::-1]


def reverse_inverse(data: str, key: Optional[str] = None) -> str:
    """Reversal is its own inverse."""
    return data[::-1]


# --------------------------------------------------------------------------
# 4. Escape-sequence obfuscation (\xNN / \uXXXX)
# --------------------------------------------------------------------------


def escape_sequence_obfuscation(data: str, key: Optional[str] = None) -> str:
    """Render every character as a ``\\xNN`` (ASCII) or ``\\uXXXX`` escape."""
    parts: list[str] = []
    for char in data:
        codepoint = ord(char)
        if codepoint < 0x80:
            parts.append(f"\\x{codepoint:02x}")
        else:
            parts.append(f"\\u{codepoint:04x}")
    return "".join(parts)


def escape_sequence_inverse(data: str, key: Optional[str] = None) -> str:
    """Inverse of :func:`escape_sequence_obfuscation` (parses the escapes)."""
    import re

    if not data:
        return ""
    tokens = re.findall(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})", data)
    if not tokens:
        raise ObfuscatorError("input does not look like an escape sequence")
    # tokens are (x_hex, u_hex) pairs; exactly one side is populated per match.
    return "".join(chr(int(x_hex or u_hex, 16)) for x_hex, u_hex in tokens)


# --------------------------------------------------------------------------
# Uniform registry
# --------------------------------------------------------------------------

TechniqueFn = Callable[[str, Optional[str]], str]

# technique name -> (obfuscate, deobfuscate, human label)
TECHNIQUES: dict[str, tuple[TechniqueFn, TechniqueFn, str]] = {
    "insert": (random_char_insertion, random_char_removal, "Random char insertion"),
    "split": (split_and_concat, split_join_inverse, "Split & concat"),
    "reverse": (reverse_transform, reverse_inverse, "String reversal"),
    "escape": (escape_sequence_obfuscation, escape_sequence_inverse, "Escape sequences"),
}

AVAILABLE_TECHNIQUES: list[str] = list(TECHNIQUES)


def obfuscate(data: str, technique: str, key: Optional[str] = None) -> str:
    """Apply a named obfuscation technique."""
    try:
        func, _, _ = TECHNIQUES[technique]
    except KeyError:
        raise ObfuscatorError(
            f"unknown technique '{technique}' (choose from {', '.join(AVAILABLE_TECHNIQUES)})"
        ) from None
    return func(data, key)


def deobfuscate(data: str, technique: str, key: Optional[str] = None) -> str:
    """Reverse a named obfuscation technique."""
    try:
        _, inverse, _ = TECHNIQUES[technique]
    except KeyError:
        raise ObfuscatorError(
            f"unknown technique '{technique}' (choose from {', '.join(AVAILABLE_TECHNIQUES)})"
        ) from None
    return inverse(data, key)


def technique_label(technique: str) -> str:
    """Human-readable label for a technique name."""
    return TECHNIQUES[technique][2]
