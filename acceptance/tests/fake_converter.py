#!/usr/bin/env python3
"""TEST-ONLY stand-in for the converter, used to exercise the harness itself.

usage: fake_converter.py SOURCE OUTDIR [--include-secrets]

The self-test source is already Ferrum resources JSON. Keys starting with
``x_`` stand for credential input: ``copy`` mode drops them, ``leak`` mode
echoes them into the report (a deliberate bug the harness must catch),
``reject`` mode emits only a report with an error, and ``liar`` mode writes
resources plus a report error but exits 0 (an exit-code/report contradiction
the harness must catch).
"""

import json
import os
import sys
from pathlib import Path


def main() -> int:
    source, outdir = Path(sys.argv[1]), Path(sys.argv[2])
    mode = os.environ.get("FAKE_CONVERTER_MODE", "copy")
    outdir.mkdir(parents=True, exist_ok=True)
    doc = json.loads(source.read_text(encoding="utf-8"))
    hidden = {k: v for k, v in doc.items() if k.startswith("x_")}
    clean = {k: v for k, v in doc.items() if not k.startswith("x_")}
    caveats = []
    if hidden:
        caveats.append({"severity": "warning", "code": "credential_withheld", "source": "selftest",
                        "message": f"{len(hidden)} credential value(s) withheld"})
    if mode == "leak":
        caveats.append({"severity": "info", "code": "debug", "source": "selftest",
                        "message": "values: " + ", ".join(str(v) for v in hidden.values())})
    if mode in ("reject", "liar"):
        caveats.append({"severity": "error", "code": "unsupported", "source": "selftest",
                        "message": "refused for self-test"})
    if mode != "reject":
        (outdir / "resources.json").write_text(json.dumps(clean, indent=2), encoding="utf-8")
    counts = {s: sum(1 for c in caveats if c["severity"] == s) for s in ("error", "warning", "info")}
    report = {"tool": "ferrum-migration", "platform": "selftest", "counts": counts, "caveats": caveats}
    (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 1 if mode == "reject" else 0


if __name__ == "__main__":
    sys.exit(main())
