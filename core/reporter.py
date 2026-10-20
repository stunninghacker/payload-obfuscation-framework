"""Report generation: compare raw vs encoded/obfuscated variants and score them.

Pipeline: original string -> every encoder/obfuscator -> detector scan ->
comparison table (terminal) + JSON/text reports on disk + summary stats.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .detector import SignatureDetector
from .encoders import AVAILABLE_METHODS, encode
from .obfuscators import AVAILABLE_TECHNIQUES, obfuscate, technique_label

# Default location for generated reports (created on demand).
DEFAULT_REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"

PREVIEW_LEN = 48  # characters of each variant shown in tables/reports


@dataclass
class VariantResult:
    """Detector outcome for one transformed variant of the payload."""

    name: str
    technique: str
    kind: str  # "original" | "encode" | "obfuscate"
    output: str
    detected: bool
    matches: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return "CAUGHT" if self.detected else "BYPASSED"

    @property
    def preview(self) -> str:
        text = self.output.replace("\n", "\\n")
        if len(text) > PREVIEW_LEN:
            return text[:PREVIEW_LEN] + "…"
        return text or "(empty)"


@dataclass
class Analysis:
    """Full comparison run for one original payload."""

    payload: str
    results: list[VariantResult]
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    # -- summary statistics -------------------------------------------------

    @property
    def overall_bypass_rate(self) -> float:
        variants = [r for r in self.results if r.kind != "original"]
        if not variants:
            return 0.0
        bypassed = sum(1 for r in variants if not r.detected)
        return bypassed / len(variants)

    def bypass_rate_by_technique(self) -> dict[str, float]:
        """Bypass rate grouped by technique name (encode/obfuscate methods)."""
        groups: dict[str, list[bool]] = {}
        for result in self.results:
            if result.kind == "original":
                continue
            groups.setdefault(result.technique, []).append(result.detected)
        return {
            name: sum(1 for d in detected_flags if not d) / len(detected_flags)
            for name, detected_flags in groups.items()
        }


# --------------------------------------------------------------------------
# Building variants
# --------------------------------------------------------------------------


def build_variants(payload: str, key: Optional[str] = "hexkey") -> list[VariantResult]:
    """Produce the raw string plus every encoder/obfuscator variant, scanned."""
    detector = SignatureDetector.from_json()
    results: list[VariantResult] = []

    # 1. Original (baseline — we expect the detector to CATCH this).
    scan = detector.scan(payload)
    results.append(
        VariantResult(
            name="original (raw)",
            technique="none",
            kind="original",
            output=payload,
            detected=scan.detected,
            matches=[m.signature.name for m in scan.matches],
        )
    )

    # 2. Encoders.
    for method in AVAILABLE_METHODS:
        try:
            encoded = encode(payload, method, key)
        except Exception as exc:  # e.g. xor without a key
            results.append(
                VariantResult(f"encode/{method}", method, "encode", f"ERROR: {exc}", False)
            )
            continue
        scan = detector.scan(encoded)
        results.append(
            VariantResult(
                name=f"encode/{method}",
                technique=method,
                kind="encode",
                output=encoded,
                detected=scan.detected,
                matches=[m.signature.name for m in scan.matches],
            )
        )

    # 3. Obfuscators.
    for technique in AVAILABLE_TECHNIQUES:
        try:
            obfuscated = obfuscate(payload, technique)
        except Exception as exc:
            results.append(
                VariantResult(
                    f"obfuscate/{technique}", technique, "obfuscate", f"ERROR: {exc}", False
                )
            )
            continue
        scan = detector.scan(obfuscated)
        results.append(
            VariantResult(
                name=f"obfuscate/{technique}",
                technique=technique,
                kind="obfuscate",
                output=obfuscated,
                detected=scan.detected,
                matches=[m.signature.name for m in scan.matches],
            )
        )

    return results


def run_analysis(payload: str, key: Optional[str] = "hexkey") -> Analysis:
    """Run the full Input -> Encode/Obfuscate -> Detect -> Report pipeline."""
    return Analysis(payload=payload, results=build_variants(payload, key))


# --------------------------------------------------------------------------
# Terminal rendering
# --------------------------------------------------------------------------


def _verdict_text(result: VariantResult) -> Text:
    if result.detected:
        return Text("CAUGHT", style="bold red")
    return Text("BYPASSED", style="bold yellow")


def render_table(console: Console, analysis: Analysis) -> None:
    """Render the comparison as a rich table (CAUGHT red / BYPASSED yellow)."""
    table = Table(title=f"Signature detection comparison — payload: {analysis.payload!r}")
    table.add_column("Variant", style="cyan")
    table.add_column("Technique")
    table.add_column("Verdict", justify="center")
    table.add_column("Matched rules", style="dim")
    table.add_column("Output preview", style="dim", overflow="fold")

    for result in analysis.results:
        table.add_row(
            result.name,
            result.technique,
            _verdict_text(result),
            ", ".join(result.matches) or "-",
            result.preview,
        )
    console.print(table)


def render_summary(console: Console, analysis: Analysis) -> None:
    """Print bypass-rate summary stats below the table."""
    summary = Table(title="Evasion effectiveness summary")
    summary.add_column("Technique", style="cyan")
    summary.add_column("Bypass rate", justify="right")

    for name, rate in analysis.bypass_rate_by_technique().items():
        style = "green" if rate >= 0.5 else "red"
        summary.add_row(name, Text(f"{rate:.0%}", style=style))

    overall = analysis.overall_bypass_rate
    summary.add_row("OVERALL", Text(f"{overall:.0%}", style="bold green" if overall >= 0.5 else "bold red"))
    console.print(summary)
    console.print(
        "[dim]Educational takeaway: a static signature engine sees only the "
        "literal transformed bytes, so trivially-reversible encodings/obfuscations "
        "score as 'BYPASSED'. Real defenses pair signatures with behavioural "
        "analysis and sandboxing.[/dim]"
    )


# --------------------------------------------------------------------------
# File reports
# --------------------------------------------------------------------------


def write_reports(analysis: Analysis, out_dir: str | Path | None = None) -> tuple[Path, Path]:
    """Write JSON + human-readable .txt reports; return their paths."""
    out_path = Path(out_dir) if out_dir else DEFAULT_REPORT_DIR
    out_path.mkdir(parents=True, exist_ok=True)
    # Microsecond stamp so batch runs never overwrite each other's files.
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    json_file = out_path / f"report_{stamp}.json"
    txt_file = out_path / f"report_{stamp}.txt"

    payload_doc = {
        "payload": analysis.payload,
        "generated_at": analysis.generated_at,
        "overall_bypass_rate": round(analysis.overall_bypass_rate, 3),
        "bypass_rate_by_technique": {
            name: round(rate, 3) for name, rate in analysis.bypass_rate_by_technique().items()
        },
        "variants": [
            {
                "name": r.name,
                "technique": r.technique,
                "kind": r.kind,
                "verdict": r.verdict,
                "output": r.output,
                "matched_rules": r.matches,
            }
            for r in analysis.results
        ],
    }
    json_file.write_text(json.dumps(payload_doc, indent=2), encoding="utf-8")

    lines = [
        "payload-obfuscation-framework — detection comparison report",
        "=" * 60,
        f"Generated : {analysis.generated_at}",
        f"Payload   : {analysis.payload!r}",
        f"Overall bypass rate: {analysis.overall_bypass_rate:.0%}",
        "",
        f"{'Variant':<24}{'Verdict':<12}{'Matched rules':<30}Output preview",
        "-" * 60,
    ]
    for r in analysis.results:
        lines.append(
            f"{r.name:<24}{r.verdict:<12}{', '.join(r.matches) or '-':<30}{r.preview}"
        )
    lines += ["", "Bypass rate by technique:"]
    for name, rate in analysis.bypass_rate_by_technique().items():
        lines.append(f"  {name:<20} {rate:.0%}")
    txt_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return json_file, txt_file
