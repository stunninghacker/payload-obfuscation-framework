#!/usr/bin/env python3
"""payload-obfuscation-framework — educational CLI (lab exercise only).

Demonstrates how reversible encoding/obfuscation defeats a naive static
signature matcher that the project itself defines. It never generates
malware and never talks to a network; all "detection" is a toy regex /
keyword engine in core/detector.py.

Flow: Input -> Encode/Obfuscate -> Test (mock detector) -> Report
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from core import (
    deobfuscate,
    decode,
    decode_layers,
    encode,
    encode_layers,
    obfuscate,
    render_summary,
    render_table,
    run_analysis,
    write_reports,
)
from core.encoders import AVAILABLE_METHODS, EncoderError
from core.obfuscators import AVAILABLE_TECHNIQUES, ObfuscatorError, technique_label
from core.reporter import DEFAULT_REPORT_DIR

console = Console()
err_console = Console(stderr=True, style="bold red")


def _preview(text: str, limit: int = 72) -> str:
    text = text.replace("\n", "\\n")
    return text if len(text) <= limit else text[:limit] + "…"


def _split_layers(raw: Optional[str]) -> Optional[list[str]]:
    if not raw:
        return None
    return [layer.strip() for layer in raw.split(",") if layer.strip()]


# --------------------------------------------------------------------------
# Subcommand handlers
# --------------------------------------------------------------------------


def cmd_encode(args: argparse.Namespace) -> int:
    """Encode (or decode) a string with one method or a layer chain."""
    layers = _split_layers(args.layers)
    try:
        if layers:
            result = (
                decode_layers(args.input, layers, args.key)
                if args.decode
                else encode_layers(args.input, layers, args.key)
            )
            label = " > ".join(reversed(layers)) if args.decode else " > ".join(layers)
        else:
            method = args.method or "base64"
            result = decode(args.input, method, args.key) if args.decode else encode(
                args.input, method, args.key
            )
            label = method
    except EncoderError as exc:
        err_console.print(str(exc))
        return 1

    verb = "Decoded" if args.decode else "Encoded"
    table = Table(title=f"{verb} ({label})")
    table.add_column("Input", style="dim")
    table.add_column("Output", style="cyan")
    table.add_row(args.input, result)
    console.print(table)

    # Prove reversibility when encoding.
    if not args.decode:
        check = (
            decode_layers(result, layers, args.key)
            if layers
            else decode(result, args.method or "base64", args.key)
        )
        ok = check == args.input
        console.print(
            f"[green]roundtrip check: decode(encode(x)) == x -> {ok}[/green]"
            if ok
            else f"[red]roundtrip check FAILED ({check!r})[/red]"
        )
        return 0 if ok else 1
    return 0


def cmd_obfuscate(args: argparse.Namespace) -> int:
    """Obfuscate (or de-obfuscate) a string with one technique."""
    technique = args.technique
    try:
        result = (
            deobfuscate(args.input, technique)
            if args.decode
            else obfuscate(args.input, technique)
        )
    except ObfuscatorError as exc:
        err_console.print(str(exc))
        return 1

    verb = "De-obfuscated" if args.decode else "Obfuscated"
    table = Table(title=f"{verb} — {technique_label(technique)}")
    table.add_column("Input", style="dim")
    table.add_column("Output", style="cyan")
    table.add_row(args.input, result)
    console.print(table)

    if not args.decode:
        check = deobfuscate(result, technique)
        ok = check == args.input
        console.print(
            f"[green]roundtrip check: deobfuscate(obfuscate(x)) == x -> {ok}[/green]"
            if ok
            else f"[red]roundtrip check FAILED ({check!r})[/red]"
        )
        return 0 if ok else 1
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Scan the raw string and every transformed variant; show comparison."""
    analysis = run_analysis(args.input)
    if not args.all:
        # Keep only the baseline plus the requested technique (if any).
        keep = {"original (raw)"}
        if args.technique:
            keep.add(f"encode/{args.technique}")
            keep.add(f"obfuscate/{args.technique}")
        else:
            keep = {"original (raw)", "encode/base64", "obfuscate/reverse"}
        analysis.results = [r for r in analysis.results if r.name in keep]

    render_table(console, analysis)
    render_summary(console, analysis)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Batch-analyze every line of a sample file and write reports."""
    src = Path(args.file)
    if not src.exists():
        err_console.print(f"sample file not found: {src}")
        return 1

    lines = [
        line.strip()
        for line in src.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        err_console.print("no payloads found in file")
        return 1

    all_payloads = []
    total_variants = total_bypassed = 0
    for payload in lines:
        analysis = run_analysis(payload)
        all_payloads.append(analysis)
        render_table(console, analysis)
        variants = [r for r in analysis.results if r.kind != "original"]
        total_variants += len(variants)
        total_bypassed += sum(1 for r in variants if not r.detected)

    rate = total_bypassed / total_variants if total_variants else 0.0
    console.print(
        f"\n[bold]Batch summary:[/bold] {len(lines)} payloads, "
        f"{total_bypassed}/{total_variants} variants bypassed ({rate:.0%})"
    )

    out_dir = Path(args.out) if args.out else DEFAULT_REPORT_DIR
    written: list[Path] = []
    for analysis in all_payloads:
        json_file, txt_file = write_reports(analysis, out_dir)
        written.extend([json_file, txt_file])
    console.print(f"[green]wrote {len(written)} report files to {out_dir}[/green]")
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    """Decode/de-obfuscate convenience command (proves reversibility)."""
    args.decode = True
    if args.obfuscate:
        args.technique = args.method or "reverse"
        return cmd_obfuscate(args)
    args.layers = None
    return cmd_encode(args)


# --------------------------------------------------------------------------
# CLI wiring
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="payload-obfuscation-framework",
        description=(
            "Educational lab tool: shows why naive signature detection is limited. "
            "Operates only on user-supplied test strings against a self-contained "
            "mock detector. No malware, no network, no real evasion."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # encode
    p_encode = sub.add_parser("encode", help="encode a test string")
    p_encode.add_argument("--input", required=True, help="test string to encode")
    p_encode.add_argument("--method", choices=AVAILABLE_METHODS, default="base64")
    p_encode.add_argument("--key", default="hexkey", help="key for xor method")
    p_encode.add_argument(
        "--layers", help="comma-separated chain, e.g. rot13,xor,base64"
    )
    p_encode.add_argument("--decode", action="store_true", help="decode instead")
    p_encode.set_defaults(func=cmd_encode)

    # obfuscate
    p_obf = sub.add_parser("obfuscate", help="obfuscate a test string")
    p_obf.add_argument("--input", required=True, help="test string to obfuscate")
    p_obf.add_argument("--technique", choices=AVAILABLE_TECHNIQUES, required=True)
    p_obf.add_argument("--decode", action="store_true", help="de-obfuscate instead")
    p_obf.set_defaults(func=cmd_obfuscate)

    # test
    p_test = sub.add_parser("test", help="scan raw + transformed variants")
    p_test.add_argument("--input", required=True, help="test string to analyze")
    p_test.add_argument("--all", action="store_true", help="run every technique")
    p_test.add_argument(
        "--technique",
        choices=AVAILABLE_METHODS + AVAILABLE_TECHNIQUES,
        help="limit the comparison to one technique",
    )
    p_test.set_defaults(func=cmd_test)

    # report
    p_rep = sub.add_parser("report", help="batch analysis over a sample file")
    p_rep.add_argument("--file", default="samples/test_payloads.txt")
    p_rep.add_argument("--out", default=str(DEFAULT_REPORT_DIR))
    p_rep.set_defaults(func=cmd_report)

    # decode (convenience)
    p_dec = sub.add_parser("decode", help="decode/de-obfuscate to prove reversibility")
    p_dec.add_argument("--input", required=True)
    p_dec.add_argument("--method", choices=AVAILABLE_METHODS + AVAILABLE_TECHNIQUES)
    p_dec.add_argument("--key", default="hexkey")
    p_dec.add_argument("--obfuscate", action="store_true", help="treat --method as an obfuscation technique")
    p_dec.set_defaults(func=cmd_decode)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
