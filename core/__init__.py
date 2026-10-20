"""Core package for the payload-obfuscation-framework (lab/teaching use only)."""

from .detector import SignatureDetector
from .encoders import decode, decode_layers, encode, encode_layers
from .obfuscators import deobfuscate, obfuscate
from .reporter import run_analysis, render_summary, render_table, write_reports

__all__ = [
    "SignatureDetector",
    "encode",
    "decode",
    "encode_layers",
    "decode_layers",
    "obfuscate",
    "deobfuscate",
    "run_analysis",
    "render_table",
    "render_summary",
    "write_reports",
]
