#!/usr/bin/env python3
"""Runtime acceptance harness for ferrum-migration → Ferrum Edge v0.9.21.

Examples
--------
List cases:
    python3 acceptance/run.py --list

Full runtime run (converter + validate + loopback requests):
    python3 acceptance/run.py --ferrum-bin /path/to/ferrum-edge \
        --converter-env PYTHONPATH=/path/to/ferrum-migration/src

Representative smoke for all five sources (what CI gates on):
    python3 acceptance/run.py --ferrum-bin /path/to/ferrum-edge --strict --require-behavioral \
        --converter-env PYTHONPATH=/path/to/ferrum-migration/src \
        --case kong-dbless-smoke --case kong-deck-smoke --case nginx-proxy-pass-uri \
        --case traefik-smoke --case envoy-smoke --case istio-smoke

Converter-only gates (no Ferrum binary):
    python3 acceptance/run.py --no-ferrum

Every external command is an argv list (JSON) or a single binary path and is
executed without a shell.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness import FERRUM_EDGE_REFERENCE_COMMIT, HARNESS_VERSION  # noqa: E402
from harness import ferrum as ferrum_mod  # noqa: E402
from harness.cases import ADAPTERS, CaseError, load_cases  # noqa: E402
from harness.converter import ConverterProfile  # noqa: E402
from harness.procs import install_signal_cleanup, stop_all_active  # noqa: E402
from harness.runner import (  # noqa: E402
    BEHAVIORAL_CONVERSION, BLOCKED, ERROR, FAIL, PASS, REJECTED_ACCEPTABLE, SKIPPED, STATIC_ONLY,
    RunContext, run_case, write_results,
)
from harness.upstream import load_upstream_profile  # noqa: E402
from harness.util import SyntheticCanaries, TemplateError, parse_key_value  # noqa: E402


def _argv_json(value: str, flag: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except ValueError:
        raise SystemExit(f"{flag} must be a JSON list of strings")
    if not isinstance(parsed, list) or not parsed or not all(isinstance(x, str) for x in parsed):
        raise SystemExit(f"{flag} must be a non-empty JSON list of strings")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--fixtures", type=Path, default=HERE / "fixtures")
    p.add_argument("--case", action="append", default=[], help="run only this case id (repeatable)")
    p.add_argument("--adapter", action="append", default=[], choices=ADAPTERS, help="run only this adapter (repeatable)")
    p.add_argument("--list", action="store_true", help="list cases and exit")
    g = p.add_argument_group("converter")
    g.add_argument("--converter-profile", type=Path, default=HERE / "profiles" / "converter.default.json")
    g.add_argument("--converter-argv", help="JSON argv template overriding the profile argv")
    g.add_argument("--converter-env", action="append", default=[], metavar="KEY=VALUE")
    g = p.add_argument_group("ferrum")
    g.add_argument("--ferrum-bin", default=os.environ.get("FERRUM_EDGE_BIN"), help="ferrum-edge binary (or $FERRUM_EDGE_BIN)")
    g.add_argument("--ferrum-argv", help="JSON argv prefix for ferrum-edge (overrides --ferrum-bin)")
    g.add_argument("--expect-ferrum-version", default=ferrum_mod.EXPECTED_FERRUM_VERSION)
    g.add_argument("--allow-version-mismatch", action="store_true")
    g.add_argument("--no-ferrum", action="store_true", help="converter/credential/report gates only")
    g.add_argument("--startup-timeout", type=float, default=45.0)
    g.add_argument("--request-timeout", type=float, default=10.0)
    g.add_argument("--mesh-validate-env", action="append", default=None, metavar="KEY=VALUE",
                   help="env for `validate -m mesh` when the converter emits a mesh slice")
    g.add_argument("--strict-mesh", action="store_true", help="fail cases whose mesh slice does not validate")
    g = p.add_argument_group("upstream differential (optional)")
    g.add_argument("--upstream-profile", type=Path, help="JSON profile: adapter -> argv/env to run the source product")
    g = p.add_argument_group("run control")
    g.add_argument("--pass-env", action="append", default=[], metavar="NAME", help="inherit this env var into children")
    g.add_argument("--work-root", type=Path,
                   help="parent under which each run creates a fresh private run-* directory for its per-case "
                        "work dirs; existing entries are never reused or removed (default: new temp dir)")
    g.add_argument("--keep-workdirs", action="store_true",
                   help="keep every case work dir (non-passing cases always keep theirs)")
    g.add_argument("--results", type=Path, help="write machine-readable results JSON here")
    g.add_argument("--strict", action="store_true", help="BLOCKED/SKIPPED/STATIC_ONLY also fail the run")
    g.add_argument("--require-behavioral", action="store_true",
                   help="every selected case must PASS as a behavioral conversion (a forwarded probe); "
                        "safe refusals and deny-only passes fail the run (use for smoke gates)")
    return p


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)
    install_signal_cleanup()
    try:
        cases = load_cases(args.fixtures)
    except CaseError as exc:
        print(f"fixture error: {exc}", file=sys.stderr)
        return 2
    if args.case:
        wanted = set(args.case)
        unknown = wanted - {c.id for c in cases}
        if unknown:
            print(f"unknown case id(s): {sorted(unknown)}", file=sys.stderr)
            return 2
        cases = [c for c in cases if c.id in wanted]
    if args.adapter:
        cases = [c for c in cases if c.adapter in set(args.adapter)]
    if args.list:
        for c in cases:
            flags = []
            if c.allow_rejection:
                flags.append("refusal-acceptable")
            if c.deny_only:
                flags.append("deny-only")
            if c.include_secrets:
                flags.append("include-secrets")
            print(f"{c.id:40s} {c.adapter:12s} {', '.join(flags)}")
        return 0
    if not cases:
        print("no cases selected", file=sys.stderr)
        return 2

    try:
        converter_argv = _argv_json(args.converter_argv, "--converter-argv") if args.converter_argv else None
        profile = ConverterProfile.load(args.converter_profile, converter_argv)
        converter_env = parse_key_value(args.converter_env, "--converter-env")
        mesh_env = parse_key_value(args.mesh_validate_env, "--mesh-validate-env") if args.mesh_validate_env is not None else None
        upstream = load_upstream_profile(args.upstream_profile) if args.upstream_profile else None
    except (OSError, ValueError, TemplateError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if profile.assumed:
        print(
            "WARNING: converter profile marks its argv as ASSUMED; results may not reflect the real CLI.",
            file=sys.stderr,
        )

    prefix = None
    if not args.no_ferrum:
        if args.ferrum_argv:
            prefix = _argv_json(args.ferrum_argv, "--ferrum-argv")
        elif args.ferrum_bin:
            prefix = [args.ferrum_bin]
        else:
            print("no Ferrum binary: pass --ferrum-bin/--ferrum-argv (or $FERRUM_EDGE_BIN), or --no-ferrum", file=sys.stderr)
            return 2

    # All scratch of this run lives in a directory the run itself just created
    # (mkdtemp: fresh name, mode 0700). A caller-supplied --work-root is only a
    # parent: nothing already beneath it is reused, followed or deleted.
    if args.work_root is None:
        run_root = Path(tempfile.mkdtemp(prefix="ferrum-acceptance-")).resolve()
    else:
        work_root = args.work_root.resolve()
        work_root.mkdir(parents=True, exist_ok=True)
        run_root = Path(tempfile.mkdtemp(prefix="run-", dir=work_root))

    ferrum_opts = None
    version_info = None
    if prefix is not None:
        ferrum_opts = ferrum_mod.FerrumOptions(
            argv_prefix=prefix,
            expected_version=args.expect_ferrum_version,
            startup_timeout=args.startup_timeout,
            request_timeout=args.request_timeout,
            pass_env=tuple(args.pass_env),
        )
        try:
            version_info = ferrum_mod.check_version(ferrum_opts, run_root / "_preflight")
        except OSError as exc:
            print(f"cannot execute ferrum-edge: {type(exc).__name__}", file=sys.stderr)
            _discard_run_scratch(run_root)
            return 2
        if not version_info["ok"]:
            msg = f"ferrum-edge version is {version_info.get('version')!r}, expected {args.expect_ferrum_version!r}"
            if not args.allow_version_mismatch:
                print(f"{msg} (use --allow-version-mismatch to proceed)", file=sys.stderr)
                _discard_run_scratch(run_root)
                return 2
            print(f"WARNING: {msg}", file=sys.stderr)

    canaries = SyntheticCanaries()
    ctx = RunContext(
        work_root=run_root,
        converter=profile,
        converter_env=converter_env,
        ferrum=ferrum_opts,
        upstream=upstream,
        pass_env=list(args.pass_env),
        mesh_validate_env=mesh_env,
        strict_mesh=args.strict_mesh,
        keep_workdirs=args.keep_workdirs,
        request_timeout=args.request_timeout,
    )

    started = time.time()
    results = []
    try:
        for case in cases:
            print(f"[run ] {case.id}", flush=True)
            res = run_case(case, ctx, canaries)
            results.append(res)
            reason = (res["failures"] or res["notes"] or [""])[0]
            print(f"[{res['status']:<19}] {case.id}  ({res['outcome_kind']})  {reason[:140]}", flush=True)
    finally:
        stop_all_active()

    counts: dict[str, int] = {}
    kinds: dict[str, int] = {}
    for res in results:
        counts[res["status"]] = counts.get(res["status"], 0) + 1
        kinds[res["outcome_kind"]] = kinds.get(res["outcome_kind"], 0) + 1
    failing = {FAIL, ERROR}
    if args.strict:
        failing |= {BLOCKED, SKIPPED, STATIC_ONLY}
    exit_code = 1 if any(res["status"] in failing for res in results) else 0
    if args.require_behavioral:
        not_behavioral = [res["id"] for res in results if res["outcome_kind"] != BEHAVIORAL_CONVERSION]
        if not_behavioral:
            print("not a behavioral conversion: " + ", ".join(not_behavioral), file=sys.stderr)
            exit_code = 1

    payload = {
        "harness_version": HARNESS_VERSION,
        "ferrum_edge_reference_commit": FERRUM_EDGE_REFERENCE_COMMIT,
        "ferrum_version": version_info,
        "converter_profile": profile.source_path,
        "converter_argv_assumed": profile.assumed,
        "upstream_differential": bool(upstream),
        "started_unix": int(started),
        "seconds": round(time.time() - started, 2),
        "counts": counts,
        "outcome_kinds": kinds,
        "exit_code": exit_code,
        "status_legend": {
            PASS: "claims asserted with runtime evidence",
            REJECTED_ACCEPTABLE: "intentional safe refusal (report error or input rejected); nothing claimed",
            STATIC_ONLY: "no runtime evidence (--no-ferrum)",
            BLOCKED: "runtime skipped for isolation reasons",
            SKIPPED: "prerequisite missing",
            FAIL: "mismatch or unsafe behavior",
            ERROR: "harness problem",
        },
        "cases": results,
    }
    if args.results:
        write_results(args.results, payload, canaries.all_sensitive())
    print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print("outcomes: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    kept = [r["workdir"] for r in results if r.get("workdir")]
    if kept:
        print(f"work dirs kept under {run_root}")
    else:
        _discard_run_scratch(run_root)
    return exit_code


def _discard_run_scratch(run_root: Path) -> None:
    """Remove only what this run created: its preflight dir and its (then empty) run dir.

    ``run_root`` is always a directory this run made with mkdtemp. Case work dirs
    are removed by the runner itself; anything else left inside keeps the run dir.
    """
    shutil.rmtree(run_root / "_preflight", ignore_errors=True)
    try:
        run_root.rmdir()
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
