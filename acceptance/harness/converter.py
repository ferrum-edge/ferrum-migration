"""Invoke the ferrum-migration converter through a caller-selected argv profile.

Nothing here hard-codes the CLI: the profile JSON (default:
``profiles/converter.default.json``, which mirrors ``ferrum-migrate convert``)
supplies an argv template with ``{token}`` placeholders, the per-adapter
platform names, the extra argv that opts into credential inclusion, explicit
output filenames (content discovery is the fallback), and the exit-code
contract used to cross-check the report.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .procs import minimal_env, run_bounded
from .util import TemplateError, expand_argv, expand_env, expand_optional_argv, scrub, tail

_PROFILE_KEYS = {
    "description",
    "argv",
    "include_secrets_argv",
    "platform_names",
    "env",
    "outputs",
    "timeout_seconds",
    "assumed",
    "exit_codes",
}
_OUTPUT_KEYS = {"resources", "settings", "report", "mesh"}
_EXIT_CODE_KEYS = {"ok", "review", "input_rejected"}


@dataclass
class ConverterProfile:
    argv: list[str]
    include_secrets_argv: list[str]
    platform_names: dict[str, str]
    env: dict[str, str]
    outputs: dict[str, list[str]]
    timeout_seconds: float
    assumed: bool
    source_path: str
    exit_codes: dict[str, list[int]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path, argv_override: "list[str] | None" = None) -> "ConverterProfile":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TemplateError("converter profile must be a JSON object")
        unknown = set(data) - _PROFILE_KEYS
        if unknown:
            raise TemplateError(f"converter profile has unknown keys: {sorted(unknown)}")
        outputs = data.get("outputs") or {}
        if set(outputs) - _OUTPUT_KEYS:
            raise TemplateError("converter profile outputs may only name resources/settings/report/mesh")
        argv = argv_override if argv_override is not None else data.get("argv")
        if not isinstance(argv, list) or not argv:
            raise TemplateError("converter profile needs a non-empty argv list")
        exit_codes = data.get("exit_codes") or {}
        if not isinstance(exit_codes, dict) or set(exit_codes) - _EXIT_CODE_KEYS or not all(
                isinstance(v, list) and all(isinstance(c, int) for c in v) for v in exit_codes.values()):
            raise TemplateError("converter profile exit_codes may only map ok/review/input_rejected to integer lists")
        return cls(
            argv=list(argv),
            include_secrets_argv=list(data.get("include_secrets_argv") or []),
            platform_names=dict(data.get("platform_names") or {}),
            env=dict(data.get("env") or {}),
            outputs={key: list(value) for key, value in outputs.items()},
            timeout_seconds=float(data.get("timeout_seconds", 120)),
            assumed=bool(data.get("assumed", False)) and argv_override is None,
            source_path=str(path),
            exit_codes={key: list(value) for key, value in exit_codes.items()},
        )

    def platform(self, adapter: str) -> str:
        return self.platform_names.get(adapter, adapter)


@dataclass
class Outputs:
    resources: "Path | None" = None
    settings: "Path | None" = None
    report_path: "Path | None" = None
    report: "dict | None" = None
    mesh: "Path | None" = None
    db_artifacts: list[str] = field(default_factory=list)
    all_files: list[Path] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


@dataclass
class ConversionResult:
    argv_display: list[str]
    returncode: "int | None"
    timed_out: bool
    stdout: str
    stderr: str
    outputs: Outputs


def _walk(outdir: Path, max_files: int = 200, max_depth: int = 3) -> list[Path]:
    found: list[Path] = []
    stack = [(outdir, 0)]
    while stack and len(found) < max_files:
        current, depth = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir() and depth < max_depth:
                stack.append((entry, depth + 1))
            elif entry.is_file():
                found.append(entry)
    return found


def _read_text(path: Path, limit: int = 8_000_000) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


_PROXIES_YAML = re.compile(r"(?m)^proxies\s*:")
_MESH_YAML = re.compile(r"(?m)^mesh\s*:")


def discover_outputs(outdir: Path, profile: ConverterProfile) -> Outputs:
    out = Outputs()
    files = _walk(outdir)
    out.all_files = files

    def named(kind: str) -> "Path | None":
        for name in profile.outputs.get(kind, []):
            candidate = outdir / name
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        return None

    # Report: explicit name, else a JSON document that identifies itself.
    out.report_path = named("report")
    if out.report_path is None:
        for path in files:
            if path.suffix == ".json":
                try:
                    doc = json.loads(_read_text(path))
                except ValueError:
                    continue
                if isinstance(doc, dict) and doc.get("tool") == "ferrum-migration":
                    out.report_path = path
                    break
    if out.report_path is not None:
        try:
            doc = json.loads(_read_text(out.report_path))
            out.report = doc if isinstance(doc, dict) else None
        except ValueError:
            out.problems.append("report file is not valid JSON")

    out.resources = named("resources")
    if out.resources is None:
        candidates = []
        for path in files:
            if path == out.report_path or path.suffix not in (".yaml", ".yml", ".json"):
                continue
            text = _read_text(path)
            if _PROXIES_YAML.search(text) or (path.suffix == ".json" and '"proxies"' in text):
                candidates.append(path)
        if len(candidates) == 1:
            out.resources = candidates[0]
        elif candidates:
            preferred = [p for p in candidates if p.name.startswith("resources")]
            if len(preferred) == 1:
                out.resources = preferred[0]
            else:
                out.problems.append(
                    "multiple resource-like files; set outputs.resources in the converter profile"
                )

    out.mesh = named("mesh")
    if out.mesh is None:
        for path in files:
            if path in (out.resources, out.report_path) or path.suffix not in (".yaml", ".yml"):
                continue
            if _MESH_YAML.search(_read_text(path)):
                out.mesh = path
                break

    out.settings = named("settings")
    if out.settings is None:
        confs = [p for p in files if p.suffix == ".conf"]
        if len(confs) == 1:
            out.settings = confs[0]
        elif confs:
            exact = [p for p in confs if p.name == "ferrum.conf"]
            out.settings = exact[0] if exact else None

    out.db_artifacts = sorted(
        p.name for p in files if re.search(r"(batch|restore)", p.name, re.IGNORECASE)
    )
    return out


def run_converter(
    profile: ConverterProfile,
    adapter: str,
    case_id: str,
    source: Path,
    outdir: Path,
    workdir: Path,
    include_secrets: bool,
    extra_env: dict[str, str],
    pass_env: "list[str] | tuple[str, ...]",
    sensitive: list[str],
) -> ConversionResult:
    outdir.mkdir(parents=True, exist_ok=True)
    values = {
        "python": sys.executable,
        "source": str(source),
        "outdir": str(outdir),
        "platform": profile.platform(adapter),
        "adapter": adapter,
        "workdir": str(workdir),
        "case_id": case_id,
    }
    argv = expand_argv(profile.argv, values)
    if include_secrets:
        extra = expand_optional_argv(profile.include_secrets_argv, values)
        if not extra:
            raise TemplateError(
                "case requires credential inclusion but the converter profile has no include_secrets_argv"
            )
        argv += extra
    cwd = workdir / "converter-cwd"
    cwd.mkdir(parents=True, exist_ok=True)
    env = minimal_env(workdir, pass_env)
    env.update(expand_env(profile.env, values))
    env.update(extra_env)
    result = run_bounded("converter", argv, cwd, env, workdir / "logs", profile.timeout_seconds)
    outputs = discover_outputs(outdir, profile)
    return ConversionResult(
        argv_display=[scrub(item, sensitive) for item in argv],
        returncode=result.returncode,
        timed_out=result.timed_out,
        stdout=result.stdout,
        stderr=result.stderr,
        outputs=outputs,
    )


def report_findings(report: "dict | None") -> "list[dict] | None":
    if not isinstance(report, dict):
        return None
    caveats = report.get("caveats")
    if not isinstance(caveats, list):
        return []
    findings = []
    for item in caveats:
        if isinstance(item, dict):
            findings.append(
                {
                    "severity": str(item.get("severity", "")).lower(),
                    "code": str(item.get("code", "")),
                    "message": str(item.get("message", "")),
                    "source": str(item.get("source", "")),
                    "action": str(item.get("action", "")),
                }
            )
    return findings


def severity_counts(report: "dict | None") -> dict[str, int]:
    counts = {"error": 0, "warning": 0, "info": 0}
    findings = report_findings(report) or []
    for item in findings:
        if item["severity"] in counts:
            counts[item["severity"]] += 1
    declared = report.get("counts") if isinstance(report, dict) else None
    if isinstance(declared, dict):
        for key in counts:
            value = declared.get(key)
            if isinstance(value, int) and value > counts[key]:
                counts[key] = value
    return counts


def findings_mention(report: "dict | None", needles: list[str]) -> bool:
    findings = report_findings(report) or []
    lowered = [n.lower() for n in needles]
    for item in findings:
        if item["severity"] not in ("error", "warning"):
            continue
        haystack = " ".join((item["code"], item["message"], item["source"])).lower()
        if any(needle in haystack for needle in lowered):
            return True
    return False


def exit_code_verdict(profile: ConverterProfile, returncode: "int | None", report: "dict | None") -> tuple[list[str], bool]:
    """Cross-check the converter exit code against its report.

    Returns ``(failures, input_rejected)``. With the real contract, exit 0 must
    come with zero report errors, exit 4 with at least one, and exit 3 means the
    input was rejected before anything was written. Any other code fails.
    Without an ``exit_codes`` contract in the profile nothing is checked.
    """
    contract = profile.exit_codes
    if not contract or returncode is None:
        return [], False
    errors = severity_counts(report)["error"] if report is not None else None
    if returncode in contract.get("input_rejected", []):
        return [], True
    if returncode in contract.get("ok", []):
        if errors:
            return [f"converter exited {returncode} (success) although its report has {errors} error finding(s)"], False
        return [], False
    if returncode in contract.get("review", []):
        if report is None:
            return [f"converter exited {returncode} (review required) but wrote no report"], False
        if not errors:
            return [f"converter exited {returncode} (review required) but its report has no error finding"], False
        return [], False
    return [f"converter exited {returncode}, which is not a success, review or input-rejected code"], False


def converter_log_tail(result: ConversionResult, sensitive: list[str]) -> str:
    return tail(scrub(result.stderr + "\n" + result.stdout, sensitive))
