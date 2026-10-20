"""Reversible string encoders used by the payload-obfuscation-framework.

LAB-ONLY EDUCATIONAL MODULE
---------------------------
These are textbook encoding routines (Base64, repeating-key XOR, ROT13).
They exist solely to demonstrate that naive signature detectors scan the
*literal* bytes of a string and therefore miss trivially-decodable variants.
Nothing here produces malware, shellcode, or real evasion tooling.
"""

from __future__ import annotations

import base64
from typing import Callable, Optional

# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class EncoderError(ValueError):
    """Raised when an encoder/decoder is given invalid arguments or data."""


# --------------------------------------------------------------------------
# Individual encoders (each is roundtrip-safe: decode(encode(x)) == x)
# --------------------------------------------------------------------------


def base64_encode(data: str, key: Optional[str] = None) -> str:
    """Encode a string as standard Base64 (ASCII-safe output)."""
    return base64.b64encode(data.encode("utf-8")).decode("ascii")


def base64_decode(data: str, key: Optional[str] = None) -> str:
    """Inverse of :func:`base64_encode`."""
    try:
        return base64.b64decode(data.encode("ascii"), validate=True).decode("utf-8")
    except Exception as exc:  # binascii.Error, UnicodeDecodeError, ...
        raise EncoderError(f"not valid Base64: {exc}") from exc


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """Repeating-key XOR of ``data`` with ``key`` (pure stdlib)."""
    if not key:
        raise EncoderError("XOR requires a non-empty key")
    # itertools-free approach: cycle the key over the data byte-by-byte.
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def xor_encode(data: str, key: Optional[str] = None) -> str:
    """Repeating-key XOR; output is hex so it stays printable/reversible."""
    if key is None:
        raise EncoderError("xor method requires --key")
    result = _xor_bytes(data.encode("utf-8"), key.encode("utf-8"))
    return result.hex()


def xor_decode(data: str, key: Optional[str] = None) -> str:
    """Inverse of :func:`xor_encode` (hex -> bytes -> XOR -> UTF-8)."""
    if key is None:
        raise EncoderError("xor method requires --key")
    try:
        raw = bytes.fromhex(data)
    except ValueError as exc:
        raise EncoderError(f"XOR output must be hex-encoded: {exc}") from exc
    return _xor_bytes(raw, key.encode("utf-8")).decode("utf-8")


# ROT13 maps a string onto itself in both directions, so one function
# serves as both encode and decode.
_ROT13_TABLE = str.maketrans(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM",
)


def rot13_encode(data: str, key: Optional[str] = None) -> str:
    """Classic ROT13 letter substitution."""
    return data.translate(_ROT13_TABLE)


def rot13_decode(data: str, key: Optional[str] = None) -> str:
    """ROT13 is its own inverse."""
    return rot13_encode(data)


# --------------------------------------------------------------------------
# Uniform registry / API
# --------------------------------------------------------------------------

EncoderFn = Callable[[str, Optional[str]], str]

ENCODERS: dict[str, tuple[EncoderFn, EncoderFn]] = {
    "base64": (base64_encode, base64_decode),
    "xor": (xor_encode, xor_decode),
    "rot13": (rot13_encode, rot13_decode),
}

AVAILABLE_METHODS: list[str] = list(ENCODERS)


def encode(data: str, method: str, key: Optional[str] = None) -> str:
    """Uniform encode interface: ``encode(data, "base64")``."""
    try:
        encoder, _ = ENCODERS[method]
    except KeyError:
        raise EncoderError(
            f"unknown method '{method}' (choose from {', '.join(AVAILABLE_METHODS)})"
        ) from None
    return encoder(data, key)


def decode(data: str, method: str, key: Optional[str] = None) -> str:
    """Uniform decode interface: ``decode(data, "base64")``."""
    try:
        _, decoder = ENCODERS[method]
    except KeyError:
        raise EncoderError(
            f"unknown method '{method}' (choose from {', '.join(AVAILABLE_METHODS)})"
        ) from None
    return decoder(data, key)


def encode_layers(data: str, layers: list[str], key: Optional[str] = None) -> str:
    """Apply a chain of encoders, e.g. ``["rot13", "xor", "base64"]``."""
    result = data
    for layer in layers:
        result = encode(result, layer, key)
    return result


def decode_layers(data: str, layers: list[str], key: Optional[str] = None) -> str:
    """Reverse a layered encoding by applying decoders in reverse order."""
    result = data
    for layer in reversed(layers):
        result = decode(result, layer, key)
    return result
