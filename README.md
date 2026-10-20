# payload-obfuscation-framework

> **Lab / classroom exercise only.** This project is an educational
> demonstration of why *naive signature-based detection* is limited. It
> operates exclusively on user-supplied test strings and scores them against a
> **self-contained mock signature engine that this project itself defines**
> (`core/detector.py` + `signatures/default_signatures.json`).
>
> - It does **not** generate malware, shellcode, or exploit code.
> - It does **not** evade or interact with any real antivirus / EDR product.
> - It makes **no network calls**; every input string stays on your machine.
>
> The "detector" is a deliberately simplified regex/keyword engine whose only
> job is to be defeated in a controlled lab so students can *see* that static
> signatures miss trivially-reversible encodings — and understand why modern
> defenses add behavioural analysis and sandboxing.

---

## Overview

`payload-obfuscation-framework` is a Python 3.11+ CLI built on the standard
library (plus `rich` for terminal output). It:

1. **Encodes** test strings (Base64, repeating-key XOR, ROT13 — single or layered).
2. **Obfuscates** them (marker-tagged random-char insertion, split & concat,
   reversal, `\xNN` escape sequences).
3. **Tests** every variant against the project's own toy signature detector.
4. **Reports** a comparison table (CAUGHT in red, BYPASSED in yellow), a
   bypass-rate summary, and JSON + text reports on disk.

Every transform is **roundtrip-safe** — `decode(encode(x)) == x` for all
methods — proven by the pytest suite in `tests/`.

## Architecture

```
Input ──► Encode ──► Obfuscate ──► Test ──► Report
  │          │           │           │         │
  │   base64/xor/rot13   │    mock signature   │
  │   (layered chains)   │    engine (regex/   │   rich table + JSON +
  │                      │    keyword, local)  │   .txt in reports/
```

| Module | Responsibility |
|---|---|
| `main.py` | argparse CLI entrypoint (`encode`, `obfuscate`, `test`, `report`, `decode`) |
| `core/encoders.py` | Base64, repeating-key XOR (hex output), ROT13; uniform `encode(data, key)` API; layered chains |
| `core/obfuscators.py` | 4 reversible string transforms with matching de-obfuscators |
| `core/detector.py` | The teaching model: static keyword/regex matcher, loads JSON signatures |
| `core/reporter.py` | Builds variants, scans them, renders tables, writes reports, computes bypass rates |
| `signatures/default_signatures.json` | Harmless sample rules (`whoami`, `eval(`, `/etc/passwd`, …) |
| `samples/test_payloads.txt` | Harmless demo strings |
| `tests/test_roundtrip.py` | pytest proof that every transform reverses cleanly |

## Install

```bash
cd payload-obfuscation-framework
python -m venv .venv
.venv\Scripts\activate        # Windows   (source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
```

## Usage

### Encode a string

```bash
python main.py encode --input "whoami" --method base64
python main.py encode --input "whoami" --method xor --key mykey
python main.py encode --input "whoami" --method rot13
python main.py encode --input "whoami" --layers rot13,xor,base64 --key mykey
```

Each encode prints a roundtrip check proving `decode(encode(x)) == x`.

### Decode / prove reversibility

```bash
python main.py encode --input "d2hvYW1p" --method base64 --decode
python main.py decode --input "d2hvYW1p" --method base64
python main.py decode --input "w~aXh~bB..." --method insert --obfuscate
```

### Obfuscate a string

```bash
python main.py obfuscate --input "whoami" --technique insert
python main.py obfuscate --input "whoami" --technique split
python main.py obfuscate --input "whoami" --technique reverse
python main.py obfuscate --input "whoami" --technique escape
python main.py obfuscate --input "imahow" --technique reverse --decode
```

### Test against the mock detector (the main demo)

```bash
python main.py test --input "whoami" --all
```

Renders a comparison table:

```
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Variant            ┃ Technique ┃  Verdict ┃ Matched rules   ┃ Output preview ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ original (raw)      │ none      │  CAUGHT  │ whoami_command  │ whoami         │
│ encode/base64       │ base64    │ BYPASSED │ -               │ d2hvYW1p       │
│ obfuscate/reverse   │ reverse   │ BYPASSED │ -               │ imahow         │
│ ...                 │           │          │                 │                │
└─────────────────────┴───────────┴──────────┴─────────────────┴────────────────┘
```

…plus a bypass-rate summary table and the educational takeaway.

### Batch report over a sample file

```bash
python main.py report --file samples/test_payloads.txt --out reports/
```

Writes paired `report_YYYYMMDD_HHMMSS.json` / `.txt` files into `reports/`.

## Running the tests

```bash
pytest tests/ -v
```

Covers every encoder and obfuscator across plain, unicode, empty, newline,
and punctuation-heavy inputs, plus a detector sanity check (raw `whoami` is
caught; its Base64 form is not).

## Why this matters (the lesson)

Signature engines that match *literal bytes* are defeated by any
lossless transform — Base64, XOR, ROT13, or even splitting a keyword into
chunks. The bypasses here are trivial on purpose: the takeaway is that
detection needs **behavioural analysis, sandboxing, and heuristics** in
addition to signatures. This tool teaches that by construction, in a safe,
offline lab.
