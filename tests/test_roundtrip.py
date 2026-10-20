"""Roundtrip tests: every encoder and obfuscator must decode back to the input.

Run with:  pytest tests/ -v
"""

from __future__ import annotations

import pytest

from core.encoders import (
    AVAILABLE_METHODS,
    decode,
    decode_layers,
    encode,
    encode_layers,
)
from core.obfuscators import (
    AVAILABLE_TECHNIQUES,
    deobfuscate,
    obfuscate,
)

# A spread of inputs: plain, regex-y, unicode, empty, punctuation-heavy.
SAMPLE_INPUTS = [
    "whoami",
    "eval(",
    "test_string_123",
    "hello world",
    "cat /etc/hosts",
    "cmd.exe /c echo hi",
    "Ünïcödé payload ✓ 日本語",
    "",
    "   spaced   ",
    "new\nline\ttab",
    'quotes "double" and \'single\'',
    "~^#%&*=+ special markers",
]

KEY = "lab-key-42"


# --------------------------------------------------------------------------
# Encoders
# --------------------------------------------------------------------------


@pytest.mark.parametrize("method", AVAILABLE_METHODS)
@pytest.mark.parametrize("data", SAMPLE_INPUTS)
def test_encoder_roundtrip(method: str, data: str) -> None:
    encoded = encode(data, method, KEY)
    assert decode(encoded, method, KEY) == data


@pytest.mark.parametrize("data", SAMPLE_INPUTS)
def test_layered_roundtrip(data: str) -> None:
    layers = ["rot13", "xor", "base64"]
    encoded = encode_layers(data, layers, KEY)
    assert decode_layers(encoded, layers, KEY) == data


def test_layered_order_matters() -> None:
    """Decoding in the wrong order must not silently produce the original."""
    layers = ["rot13", "base64"]
    encoded = encode_layers("whoami", layers, KEY)
    with pytest.raises(Exception):
        decode_layers(encoded, list(reversed(layers)), KEY)  # wrong order on purpose


# --------------------------------------------------------------------------
# Obfuscators
# --------------------------------------------------------------------------


@pytest.mark.parametrize("technique", AVAILABLE_TECHNIQUES)
@pytest.mark.parametrize("data", SAMPLE_INPUTS)
def test_obfuscator_roundtrip(technique: str, data: str) -> None:
    obfuscated = obfuscate(data, technique)
    assert deobfuscate(obfuscated, technique) == data


# --------------------------------------------------------------------------
# Detector sanity: raw "whoami" is caught; its base64 form is not
# --------------------------------------------------------------------------


def test_detector_catches_raw_but_misses_base64() -> None:
    from core.detector import SignatureDetector

    detector = SignatureDetector.from_json()
    assert detector.scan("whoami").detected is True
    assert detector.scan(encode("whoami", "base64", KEY)).detected is False
