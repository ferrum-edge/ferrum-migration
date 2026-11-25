"""Command-line interface: ``ferrum-migrate`` / ``python -m ferrum_migration``.

Exit codes:

* 0 - migrated; no error-level caveats (warnings allowed unless ``--strict``)
* 1 - internal error (no output written)
* 2 - usage error
* 3 - input rejected (syntax, limits, unsupported shape; no output written)
* 4 - output written, but it contains items that require review (error-level
  caveats: refused or fail-closed routes, unmigrated credentials...), or
  warnings with ``--strict``
* 5 - output could not be written safely
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

import yaml

from . import FERRUM_EDGE_REFERENCE_COMMIT, __version__
from .envprofile import RUN_MODES, next_steps, render
from .errors import InputError, OutputError
from .ferrum import EmitOptions, emit
from .limits import ABSOLUTE_MAX_INPUT_BYTES, Limits
from .report import Report
from .safe_load import read_input
from .sources import DESCRIPTIONS, SOURCES
from .sources.common import SourceContext
from .sources.traefik import CONTROLS_ASSERTION_FLAG
from .writer import prepare_output_dir, write_files

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_INPUT = 3
EXIT_REVIEW = 4
EXIT_OUTPUT = 5

RESOURCES_YAML = "resources.yaml"
RESOURCES_JSON = "resources.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ferrum-migrate",
        description="Offline, best-effort, fail-closed migration of gateway/proxy/mesh configuration into "
                    "Ferrum Edge file-mode resources, a ferrum.conf profile and a migration report.",
    )
    parser.add_argument("--version", action="version",
                        version=f"ferrum-migration {__version__} (Ferrum Edge reference {FERRUM_EDGE_REFERENCE_COMMIT[:12]})")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("convert", "translate a config and write output files"),
                            ("check", "translate a config and print the report without writing files")):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("input", help="path to one source config file, or '-' for stdin")
        command.add_argument("--from", dest="platform", required=True, choices=sorted(SOURCES),
                             help="source platform")
        command.add_argument("--input-format", choices=("auto", "yaml", "json", "toml", "nginx"), default="auto")
        command.add_argument("--run-mode", choices=RUN_MODES, default="file",
                             help="Ferrum operating mode the ferrum.conf profile targets (default: file)")
        command.add_argument("--tls-only", action="store_true",
                             help="disable Ferrum's plaintext listener so HTTPS-only source routes can be migrated")
        command.add_argument(CONTROLS_ASSERTION_FLAG, dest="traefik_controls_asserted", action="store_true",
                             help="Traefik only. Your scoped statement, made after verifying the Traefik deployment, "
                                  "that the input includes every effective routing, TLS and access control that "
                                  "applies to the converted routers (static, dynamic or from another provider), or "
                                  "that no additional control applies. Verify at least: static entryPoints (TLS, "
                                  "middlewares, redirections, forwarded headers, PROXY protocol, address; routers "
                                  "naming no entryPoints share the entryPoint of the others), TLS options defined "
                                  "outside the input (including a 'default' from another provider), SNI option "
                                  "conflicts, and competing routers of other providers. The tool does not verify it. "
                                  "Without it, Traefik routes that would forward traffic are refused; unresolved or "
                                  "unreproducible controls in the input (such as enabled sniStrict) are refused "
                                  "either way")
        # Removed option, kept only to refuse it explicitly: insecure backend TLS is never emitted.
        command.add_argument("--allow-insecure-backend-tls", action="store_true", help=argparse.SUPPRESS)
        command.add_argument("--strict", action="store_true", help="exit 4 on warnings too")
        command.add_argument("--max-input-bytes", type=int, default=Limits().max_input_bytes)
        if name == "convert":
            command.add_argument("--out", required=True, help="output directory (created with mode 0700)")
            command.add_argument("--force", action="store_true", help="replace existing output files")
            command.add_argument("--include-secrets", action="store_true",
                                 help="write migratable plaintext credentials (Kong key-auth keys) into the "
                                      "resources file; the file is written 0600 and must stay private")
            command.add_argument("--resources-format", choices=("yaml", "json"), default="yaml")
        else:
            command.add_argument("--json", action="store_true", help="print the report as JSON")
    sub.add_parser("platforms", help="list supported source platforms")
    return parser


def _detect_format(path: str, platform: str, requested: str) -> str:
    if platform == "nginx":
        if requested not in ("auto", "nginx"):
            raise InputError("NGINX input must use nginx configuration syntax")
        return "nginx"
    if requested == "nginx":
        raise InputError("nginx syntax is only valid with --from nginx")
    if requested != "auto":
        return requested
    lower = path.lower()
    if lower.endswith(".json"):
        return "json"
    if lower.endswith(".toml"):
        return "toml"
    return "yaml"


#: Ferrum Edge v0.9.21 file-loader hard limits (`stable_file.rs::MAX_CONFIG_FILE_BYTES`,
#: `yaml_alias_budget.rs::MAX_YAML_EVENTS_PER_PASS`).
MAX_FERRUM_RESOURCES_BYTES = 64 * 1024 * 1024
MAX_FERRUM_YAML_EVENTS = 1_000_000


def _count_yaml_events(root: object) -> int:
    """Exact YAML parser event count for a JSON/YAML-compatible Python object tree."""
    events = 4  # StreamStart, DocumentStart, DocumentEnd, StreamEnd
    stack = [root]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            events += 2  # MappingStart, MappingEnd
            for k, v in item.items():
                stack.append(k)
                stack.append(v)
        elif isinstance(item, list):
            events += 2  # SequenceStart, SequenceEnd
            stack.extend(item)
        else:
            events += 1  # Scalar
    return events


def _dump_resources(config: dict, fmt: str, platform: str) -> str:
    if fmt == "json":
        rendered = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    else:
        events = _count_yaml_events(config)
        if events > MAX_FERRUM_YAML_EVENTS:
            raise OutputError(f"generated YAML resources file has {events} events, exceeding Ferrum's "
                              f"{MAX_FERRUM_YAML_EVENTS}-event YAML limit; use --resources-format json or split the "
                              "input")
        header = (f"# Ferrum Edge file-mode resources generated by ferrum-migration {__version__} from {platform} input.\n"
                  "# Review migration-report.md before use. Placeholders labelled ferrum-migration/status: refused\n"
                  "# answer HTTP 503 by design (fail closed).\n")
        rendered = header + yaml.safe_dump(config, sort_keys=False, default_flow_style=False, allow_unicode=True,
                                           width=4096)
    size = len(rendered.encode("utf-8"))
    if size > MAX_FERRUM_RESOURCES_BYTES:
        raise OutputError(f"generated resources file is {size} bytes, exceeding Ferrum's "
                          f"{MAX_FERRUM_RESOURCES_BYTES}-byte limit; split the input or reduce distinct per-route "
                          "plugin overrides")
    return rendered


INSECURE_TLS_REFUSAL = ("ferrum-migrate: --allow-insecure-backend-tls is not supported: backend TLS verification "
                        "is always enabled in generated output. Provide the backend CA via "
                        "backend_tls_server_ca_cert_path instead. Nothing was written.")


CONTROLS_ASSERTION_SCOPE = (f"ferrum-migrate: {CONTROLS_ASSERTION_FLAG} applies only to --from traefik "
                            "(controls outside Traefik dynamic configuration); it changes nothing for other sources. "
                            "Nothing was written.")


def _run(args: argparse.Namespace) -> int:
    if args.allow_insecure_backend_tls:
        print(INSECURE_TLS_REFUSAL, file=sys.stderr)
        return EXIT_USAGE
    if args.traefik_controls_asserted and args.platform != "traefik":
        # Refused rather than ignored, so the statement is never mistaken for one about another source.
        print(CONTROLS_ASSERTION_SCOPE, file=sys.stderr)
        return EXIT_USAGE
    if args.max_input_bytes <= 0 or args.max_input_bytes > ABSOLUTE_MAX_INPUT_BYTES:
        print(f"ferrum-migrate: --max-input-bytes must be between 1 and {ABSOLUTE_MAX_INPUT_BYTES}", file=sys.stderr)
        return EXIT_USAGE
    limits = Limits(max_input_bytes=args.max_input_bytes)
    label = "stdin" if args.input == "-" else os.path.basename(args.input)
    report = Report(args.platform, label)
    include_secrets = getattr(args, "include_secrets", False)
    fmt = _detect_format(args.input, args.platform, args.input_format)
    text = read_input(args.input, limits)
    context = SourceContext(report=report, limits=limits, include_secrets=include_secrets,
                            traefik_controls_asserted=args.traefik_controls_asserted)
    plan = SOURCES[args.platform].translate(text, fmt, context)
    options = EmitOptions(include_secrets=include_secrets, tls_only=args.tls_only)
    result = emit(plan, options, report)
    resources_name = RESOURCES_JSON if getattr(args, "resources_format", "yaml") == "json" else RESOURCES_YAML
    summary = dict(result.stats)
    summary["run_mode"] = args.run_mode
    steps = next_steps(args.run_mode, resources_name, result.tls_only, result.basic_auth_used, result.secrets_emitted)
    exit_code = EXIT_REVIEW if report.has_errors or (args.strict and report.has_warnings) else EXIT_OK
    # Rendered for `check` too, so a source value that cannot be written safely in ferrum.conf syntax is rejected
    # (exit 3) by both commands, before anything is written.
    profile = render(args.run_mode, args.platform, plan.settings, result.tls_only, result.basic_auth_used,
                     resources_name)

    if args.command == "check":
        if args.json:
            print(json.dumps(report.to_json_obj(summary, steps), indent=2))
        else:
            _print_text(report, summary)
        return exit_code

    files = {
        resources_name: _dump_resources(result.config, args.resources_format, args.platform),
        "ferrum.conf": profile,
        "migration-report.json": json.dumps(report.to_json_obj(summary, steps), indent=2) + "\n",
        "migration-report.md": report.to_markdown(summary, steps),
    }
    if result.secrets_emitted:
        files[".gitignore"] = "# Generated: this directory contains plaintext credentials.\n*\n"
    directory = prepare_output_dir(args.out)
    # A resources file of the other format left by an earlier run would be stale and ambiguous: Ferrum's spec
    # discovery prefers ./resources.yaml over ./resources.json. It is never replaced or deleted, not even with --force.
    other_format = RESOURCES_YAML if resources_name == RESOURCES_JSON else RESOURCES_JSON
    write_files(directory, files, args.force, forbidden=(other_format,))
    _print_text(report, summary, details=False)
    print(f"Wrote {', '.join(sorted(name for name in files if not name.startswith('.')))} to {directory}")
    if result.secrets_emitted:
        print(f"WARNING: {resources_name} contains {result.secrets_emitted} plaintext credential(s); it was written "
              "with mode 0600. Keep it private and never commit it.", file=sys.stderr)
    return exit_code


def _print_text(report: Report, summary: dict, details: bool = True) -> None:
    print(f"ferrum-migration {__version__}: {report.platform} -> Ferrum Edge")
    for key in ("source_routes", "migrated_routes", "refused_routes", "fail_closed_placeholders", "proxies",
                "upstreams", "consumers", "plugin_configs"):
        if key in summary:
            print(f"  {key}: {summary[key]}")
    print(f"  caveats: {report.count('error')} error, {report.count('warning')} warning, {report.count('info')} info")
    if details:
        for item in report.ordered():
            line = f"  [{item.severity}] {item.code} ({item.ref}): {item.message}"
            if item.action:
                line += f" Action: {item.action}"
            print(line)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    if args.command == "platforms":
        for name in sorted(SOURCES):
            print(f"{name:8s} {DESCRIPTIONS[name]}")
        return EXIT_OK
    try:
        return _run(args)
    except InputError as exc:
        print(f"ferrum-migrate: input rejected: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except OutputError as exc:
        print(f"ferrum-migrate: output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # pragma: no cover - defensive; never echo exception text (may contain input)
        print(f"ferrum-migrate: internal error ({type(exc).__name__}); no output was written", file=sys.stderr)
        return EXIT_INTERNAL
