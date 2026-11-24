"""Per-case orchestration and result classification.

Case statuses
-------------
PASS                 Converter emitted config, Ferrum validated it, and every probe
                     observed exactly the source semantics. Only PASS cases assert
                     their ``claims``.
REJECTED_ACCEPTABLE  Intentional safe refusal, never counted as a behavioral pass:
                     the case allows refusal (or is deny-only) and the converter
                     refused with evidence (a report error, or exit code
                     "input rejected"), while every deny probe stayed
                     un-forwarded. Nothing is claimed.
STATIC_ONLY          ``--no-ferrum``: converter/credential/report gates passed;
                     no runtime evidence.
BLOCKED              Runtime refused for isolation reasons (e.g. the output
                     declares a listen_port the harness did not allocate).
SKIPPED              A prerequisite was not supplied.
FAIL                 Any mismatch, unsafe credential handling, invalid output,
                     silent route drop, exit code that contradicts the report, or
                     fixture contradicted by the upstream run.
ERROR                Harness infrastructure problem.

Every result also carries ``outcome_kind``, so reports never blur the two:
``behavioral-conversion`` (PASS with at least one forwarded probe),
``fail-closed-deny-only`` (PASS whose probes are all denials),
``safe-refusal`` (REJECTED_ACCEPTABLE), ``static-only``, or ``none``.
"""

from __future__ import annotations

import json
import secrets
import shutil
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from . import ferrum as ferrum_mod
from . import probe as http_probe
from .cases import Case, Probe
from .converter import (
    ConverterProfile,
    converter_log_tail,
    exit_code_verdict,
    findings_mention,
    run_converter,
    severity_counts,
)
from .echo import PROBE_HEADER, EchoBackend, EchoRecorder
from .procs import PortHold
from .upstream import UpstreamEntry, run_differential
from .util import (
    SyntheticCanaries,
    TemplateError,
    declared_listen_ports,
    render_source,
    scrub,
)

PASS = "PASS"
REJECTED_ACCEPTABLE = "REJECTED_ACCEPTABLE"
STATIC_ONLY = "STATIC_ONLY"
BLOCKED = "BLOCKED"
SKIPPED = "SKIPPED"
FAIL = "FAIL"
ERROR = "ERROR"

# Settings keys the harness pins through the environment (env beats ferrum.conf).
_PINNED_LISTENER_KEYS = {
    "FERRUM_PROXY_HTTP_PORT", "FERRUM_PROXY_HTTPS_PORT", "FERRUM_ADMIN_HTTP_PORT",
    "FERRUM_ADMIN_HTTPS_PORT", "FERRUM_PROXY_BIND_ADDRESS", "FERRUM_ADMIN_BIND_ADDRESS",
}
# A positive probe that was not forwarded counts as a *refusal* (rather than a
# mismatch) only with one of these statuses: no route (404/421), or a
# fail-closed placeholder route (410/500/501/503). 401/403 (auth mapping) and
# 502/504 (wrong backend wiring) are always failures. A refusal is acceptable
# only when the case allows it AND the report carries an error finding.
REFUSAL_STATUSES = {404, 410, 421, 500, 501, 503}

_LISTENER_TOKENS = {"PORT", "PORTS", "BIND", "LISTEN", "ADDR", "ADDRS", "ADDRESS", "URLS"}


def _is_listenerish(key: str) -> bool:
    return bool(_LISTENER_TOKENS.intersection(key.upper().split("_")))


@dataclass
class RunContext:
    work_root: Path
    converter: "ConverterProfile | None"
    converter_env: dict[str, str]
    ferrum: "ferrum_mod.FerrumOptions | None"
    upstream: "dict[str, UpstreamEntry] | None"
    pass_env: list[str]
    mesh_validate_env: "dict[str, str] | None"
    strict_mesh: bool
    keep_workdirs: bool
    request_timeout: float = 10.0
    sensitive_extra: list[str] = field(default_factory=list)


def _render_headers(headers: dict, values: dict) -> dict:
    return {name: render_source(value, values) for name, value in headers.items()}


def _settings_listener_keys(settings: Path) -> list[str]:
    keys = []
    try:
        text = settings.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ["<unreadable settings file>"]
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if _is_listenerish(key) and key not in _PINNED_LISTENER_KEYS:
            keys.append(key)
    return sorted(set(keys))


def _credential_violations(case: Case, conv, canaries: SyntheticCanaries) -> list[str]:
    """Synthetic credential input must never be repeated where it is not allowed.

    * The stored basic-auth hash is never a usable password: it may not appear
      in any output, report or log, with or without credential inclusion.
    * The synthetic API key may never appear in the report, settings or the
      converter's stdout/stderr; it may appear in resources only when the case
      explicitly opted into credential inclusion.
    * ``secret_free`` names are forbidden everywhere, including resources.
    """
    out = conv.outputs
    violations: list[str] = []
    texts: dict[str, str] = {"converter stdout": conv.stdout, "converter stderr": conv.stderr}
    for path in out.all_files:
        try:
            texts[f"output file {path.name}"] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    resources_label = f"output file {out.resources.name}" if out.resources else None
    for label, text in texts.items():
        if canaries.stored_hash in text:
            violations.append(
                f"unsafe credential translation: the synthetic stored password hash appears in {label}"
                " (a stored hash must be re-provisioned, never treated as a password)"
            )
        if canaries.key in text:
            is_resources = label == resources_label
            if not is_resources or not case.include_secrets or "CANARY_KEY" in case.secret_free:
                violations.append(f"synthetic API key appears in {label} where credentials must be withheld")
    return violations


def _report_failures(case: Case, report) -> list[str]:
    failures = []
    if not (case.report_min_errors or case.report_min_findings or case.report_mentions_any):
        return failures
    if report is None:
        return ["case requires report findings but no ferrum-migration report was found"]
    counts = severity_counts(report)
    if counts["error"] < case.report_min_errors:
        failures.append(f"report has {counts['error']} error finding(s); case requires >= {case.report_min_errors}")
    findings = counts["error"] + counts["warning"]
    if findings < case.report_min_findings:
        failures.append(f"report has {findings} error/warning finding(s); case requires >= {case.report_min_findings}")
    if case.report_mentions_any and not findings_mention(report, case.report_mentions_any):
        failures.append(
            "no report error/warning mentions any of: " + ", ".join(case.report_mentions_any)
        )
    return failures


def _evaluate_probe(p: Probe, resp: dict, records: list[dict]) -> dict:
    observed = [{"backend": r["backend"], "path": r["path"], "method": r["method"]} for r in records]
    out = {"probe": p.id, "method": p.method, "path": p.path, "host": p.host,
           "status": resp["status"], "transport_error": resp["error"], "observed": observed}
    if p.positive:
        out["expected"] = {"backend": p.forward_backend, "path": p.forward_path, "status": p.statuses}
        if records:
            good = all(
                r["backend"] == p.forward_backend and r["path"] == p.forward_path and r["method"] == p.method
                for r in records
            )
            out["outcome"] = "pass" if good and resp["status"] in p.statuses else "fail"
            if not good:
                out["reason"] = "forwarded to the wrong backend, path or method"
            elif resp["status"] not in p.statuses:
                out["reason"] = "client status differs from the backend response"
        elif resp["status"] in REFUSAL_STATUSES:
            out["outcome"] = "refused"
        else:
            out["outcome"] = "fail"
            out["reason"] = "request was not forwarded"
    else:
        out["expected"] = {"forwarded": False, "status": p.statuses}
        if records:
            out["outcome"] = "fail"
            out["reason"] = "SECURITY: a request that must be denied reached a backend"
        elif resp["status"] in p.statuses:
            out["outcome"] = "pass"
        elif resp["status"] in REFUSAL_STATUSES:
            out["outcome"] = "refused-deny"
        else:
            out["outcome"] = "fail"
            out["reason"] = "not forwarded, but the status is outside the expected set"
    return out


BEHAVIORAL_CONVERSION = "behavioral-conversion"
FAIL_CLOSED_DENY_ONLY = "fail-closed-deny-only"
SAFE_REFUSAL = "safe-refusal"


def outcome_kind(case: Case, status: "str | None") -> str:
    """Separate "the migration works" from "the migration safely refused"."""
    if status == PASS:
        return FAIL_CLOSED_DENY_ONLY if case.deny_only else BEHAVIORAL_CONVERSION
    if status == REJECTED_ACCEPTABLE:
        return SAFE_REFUSAL
    if status == STATIC_ONLY:
        return "static-only"
    return "none"


def run_case(case: Case, ctx: RunContext, canaries: SyntheticCanaries) -> dict:
    result = _run_case(case, ctx, canaries)
    result["outcome_kind"] = outcome_kind(case, result.get("status"))
    return result


def _run_case(case: Case, ctx: RunContext, canaries: SyntheticCanaries) -> dict:
    workdir = (ctx.work_root / case.id).resolve()
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)
    result: dict = {
        "id": case.id,
        "adapter": case.adapter,
        "title": case.title,
        "status": None,
        "claims_asserted": [],
        "claims": case.claims,
        "not_claimed": case.not_claimed,
        "not_established": list(case.not_established),
        "source_truth": "inferred-from-documentation",
        "source_semantics": case.source_semantics,
        "notes": [],
        "failures": [],
        "workdir": str(workdir),
    }
    sensitive = canaries.all_sensitive() + list(ctx.sensitive_extra)
    recorder = EchoRecorder()
    backends = {tag: EchoBackend(tag, recorder).start() for tag in ("a", "b")}
    listen_hold: "PortHold | None" = PortHold()
    try:
        values = {
            "ECHO_A_PORT": backends["a"].port,
            "ECHO_B_PORT": backends["b"].port,
            "LISTEN_PORT": listen_hold.port,
            "WORKDIR": str(workdir),
            **canaries.source_values(),
        }
        listen_port = listen_hold.port
        header_values = canaries.header_values()
        rendered = render_source(case.source.read_text(encoding="utf-8"), values)
        source_path = workdir / "input" / case.source.name
        source_path.parent.mkdir(parents=True)
        source_path.write_text(rendered, encoding="utf-8")

        # 1. Optional differential run against the real source product.
        if ctx.upstream is not None:
            entry = ctx.upstream.get(case.adapter)
            if entry is None:
                result["notes"].append("no upstream profile entry for this adapter; source semantics stay inferred")
            else:
                listen_hold.release()
                listen_hold = None
                diff = run_differential(
                    entry, case, source_path, workdir, listen_port, recorder, header_values,
                    sensitive, ctx.request_timeout, ctx.pass_env, _render_headers,
                )
                result["differential"] = diff
                if diff.get("error"):
                    result["failures"].append(f"upstream differential run failed: {diff['error']}")
                elif not all(p["confirmed"] for p in diff["probes"]):
                    bad = [p["probe"] for p in diff["probes"] if not p["confirmed"]]
                    result["failures"].append(
                        "fixture contradicted by the upstream product at runtime for probe(s): " + ", ".join(bad)
                    )
                else:
                    result["source_truth"] = "verified-against-upstream-runtime"

        # 2. Conversion.
        if ctx.converter is None:
            result["status"] = SKIPPED
            result["notes"].append("no converter profile supplied")
            return result
        outdir = workdir / "converted"
        conv = run_converter(
            ctx.converter, case.adapter, case.id, source_path, outdir, workdir,
            case.include_secrets, ctx.converter_env, ctx.pass_env, sensitive,
        )
        out = conv.outputs
        result["converter"] = {
            "argv": conv.argv_display,
            "returncode": conv.returncode,
            "timed_out": conv.timed_out,
            "resources": out.resources.name if out.resources else None,
            "settings": out.settings.name if out.settings else None,
            "report": out.report_path.name if out.report_path else None,
            "mesh": out.mesh.name if out.mesh else None,
            "report_counts": severity_counts(out.report) if out.report is not None else None,
            "log_tail": converter_log_tail(conv, sensitive),
        }
        if conv.timed_out:
            result["failures"].append("converter timed out")
        result["failures"].extend(out.problems)
        result["failures"].extend(_credential_violations(case, conv, canaries))
        exit_failures, input_rejected = exit_code_verdict(ctx.converter, conv.returncode, out.report)
        result["failures"].extend(exit_failures)
        if input_rejected:
            result["notes"].append(f"converter rejected the input (exit {conv.returncode}); nothing was written")
            if out.resources is not None:
                result["failures"].append("converter reported input rejection but wrote resources")
        else:
            result["failures"].extend(_report_failures(case, out.report))
        if out.db_artifacts:
            result["notes"].append(
                "converter emitted database-mode artifacts (" + ", ".join(out.db_artifacts) + "); "
                "/batch and /restore behavior is not exercised by this harness"
            )
            result["not_established"].append("Database-mode migration (/batch additive or /restore full-clobber)")
        if case.mesh_policy:
            result["not_established"].append("Mesh-mode enforcement of the translated policy at runtime")

        error_findings = severity_counts(out.report)["error"] if out.report is not None else 0

        if out.resources is None:
            refusal_evidence = input_rejected or error_findings >= 1
            if result["failures"]:
                result["status"] = FAIL
            elif (case.allow_rejection or case.deny_only) and refusal_evidence:
                # Nothing is exposed, so no deny probe can be forwarded, but that is a refusal,
                # not a converted behavior: it is reported as such and claims nothing.
                result["status"] = REJECTED_ACCEPTABLE
                result["notes"].append("converter refused the whole input "
                                       + ("(input rejected)" if input_rejected else "with report errors")
                                       + "; no gateway run, nothing claimed")
                result["runtime"] = {"started": False, "reason": "no resources emitted"}
            elif case.allow_rejection or case.deny_only:
                result["status"] = FAIL
                result["failures"].append("converter emitted nothing without an input rejection or report error")
            elif input_rejected:
                result["status"] = FAIL
                result["failures"].append("converter rejected the input of a supported case")
            else:
                result["status"] = FAIL
                result["failures"].append("converter produced no Ferrum resources for a supported case")
            return result

        resources_text = out.resources.read_text(encoding="utf-8", errors="replace")
        if case.backend_host_rewrite:
            applied = {}
            for name, target in case.backend_host_rewrite.items():
                applied[name] = resources_text.count(name)
                resources_text = resources_text.replace(name, target)
            result["notes"].append(
                "harness rewrote synthetic Kubernetes service hosts to 127.0.0.1 in a copy of the "
                f"resources (occurrences: {applied}); service discovery itself is not exercised"
            )
        run_dir = workdir / "ferrum-input"
        run_dir.mkdir()
        resources = run_dir / out.resources.name
        resources.write_text(resources_text, encoding="utf-8")

        declared = declared_listen_ports(resources_text)
        foreign = sorted(declared - {listen_port})
        if foreign:
            result["status"] = FAIL if result["failures"] else BLOCKED
            result["notes"].append(
                f"resources declare listen_port value(s) {foreign} the harness did not allocate; "
                "runtime skipped to keep binds isolated"
            )
            return result

        if ctx.ferrum is None:
            result["status"] = FAIL if result["failures"] else STATIC_ONLY
            return result

        # 3. Ferrum validate (file mode), with converter settings when present.
        validation = ferrum_mod.validate(ctx.ferrum, "file", resources, out.settings, workdir, "ferrum-validate")
        result["validate"] = validation
        if not validation["ok"]:
            result["failures"].append("ferrum-edge validate rejected the converter output")
            if out.settings is not None:
                bare = ferrum_mod.validate(ctx.ferrum, "file", resources, None, workdir, "ferrum-validate-nosettings")
                result["validate_without_settings"] = bare
            result["status"] = FAIL
            return result

        if out.mesh is not None:
            if ctx.mesh_validate_env is None:
                result["notes"].append("mesh output present; pass --mesh-validate-env to run `validate -m mesh`")
            else:
                mesh_v = ferrum_mod.validate(
                    ctx.ferrum, "mesh", out.mesh, None, workdir, "ferrum-validate-mesh", ctx.mesh_validate_env
                )
                result["mesh_validate"] = mesh_v
                if not mesh_v["ok"] and ctx.strict_mesh:
                    result["failures"].append("ferrum-edge validate -m mesh rejected the mesh output")

        run_settings = out.settings
        if run_settings is not None:
            risky = _settings_listener_keys(run_settings)
            if risky:
                run_settings = None
                result["notes"].append(
                    "converter settings declare listener keys not pinned by the harness ("
                    + ", ".join(risky) + "); runtime ran without the settings file"
                )

        # 4. Runtime.
        if listen_hold is not None:
            listen_hold.release()
            listen_hold = None
        try:
            gateway = ferrum_mod.start_gateway(ctx.ferrum, resources, run_settings, workdir)
        except ferrum_mod.FerrumStartupError as exc:
            result["failures"].append(f"ferrum-edge failed to start: {exc}")
            result["runtime"] = {"started": False, "log_tail": scrub(exc.output_tail, sensitive)}
            result["status"] = FAIL
            return result
        probe_results = []
        try:
            port = listen_port if declared == {listen_port} else gateway.proxy_port
            if declared:
                result["notes"].append("probes sent to the harness-allocated listen_port declared by the output")
            for p in case.probes:
                pid = f"{case.id}-{p.id}-{secrets.token_hex(4)}"
                headers = _render_headers(p.headers, header_values)
                headers[PROBE_HEADER] = pid
                resp = http_probe.send(port, p.method, p.path, p.host, headers, ctx.request_timeout)
                probe_results.append(_evaluate_probe(p, resp, recorder.for_probe(pid)))
        finally:
            gateway.stop()
            result["runtime"] = {
                "started": True,
                "proxies_loaded": gateway.proxies_loaded,
                "used_settings": run_settings is not None,
                "log_tail": gateway.output_tail(sensitive),
            }
        result["probes"] = probe_results

        refused = [r for r in probe_results if r["outcome"] == "refused"]
        refused_deny = [r for r in probe_results if r["outcome"] == "refused-deny"]
        failed = [r for r in probe_results if r["outcome"] == "fail"]
        for r in failed:
            result["failures"].append(f"probe {r['probe']}: {r.get('reason', 'mismatch')}")
        if result["failures"]:
            result["status"] = FAIL
        elif refused:
            if not case.allow_rejection:
                result["status"] = FAIL
                result["failures"].append(
                    "positive probe(s) were refused (not forwarded) in a case that does not allow refusal: "
                    + ", ".join(r["probe"] for r in refused)
                )
            elif error_findings < 1:
                result["status"] = FAIL
                result["failures"].append("route(s) silently dropped: refused without any report error finding")
            else:
                result["status"] = REJECTED_ACCEPTABLE
                result["notes"].append(
                    "refused probe(s): " + ", ".join(r["probe"] for r in refused + refused_deny)
                )
        elif refused_deny:
            if case.allow_rejection and error_findings >= 1:
                result["status"] = REJECTED_ACCEPTABLE
                result["notes"].append(
                    "deny probe(s) answered by a refusal/placeholder status (not forwarded): "
                    + ", ".join(r["probe"] for r in refused_deny)
                )
            else:
                result["status"] = FAIL
                result["failures"].append(
                    "deny probe(s) were not forwarded but answered with an unexpected refusal status: "
                    + ", ".join(r["probe"] for r in refused_deny)
                )
        else:
            result["status"] = PASS
            result["claims_asserted"] = case.claims
        return result
    except TemplateError as exc:
        result["status"] = ERROR
        result["failures"].append(f"template error: {exc}")
        return result
    except Exception as exc:  # noqa: BLE001 - classify, keep going with other cases
        result["status"] = ERROR
        result["failures"].append(f"harness error: {type(exc).__name__}: {scrub(str(exc), sensitive)}")
        result["traceback"] = scrub(traceback.format_exc(limit=8), sensitive)
        return result
    finally:
        if listen_hold is not None:
            listen_hold.release()
        for backend in backends.values():
            backend.stop()
        if result.get("status") in (PASS, REJECTED_ACCEPTABLE, STATIC_ONLY) and not ctx.keep_workdirs:
            shutil.rmtree(workdir, ignore_errors=True)
            result["workdir"] = None


def scrub_tree(obj, sensitive: list[str]):
    if isinstance(obj, str):
        return scrub(obj, sensitive)
    if isinstance(obj, list):
        return [scrub_tree(item, sensitive) for item in obj]
    if isinstance(obj, dict):
        return {key: scrub_tree(value, sensitive) for key, value in obj.items()}
    return obj


def write_results(path: Path, payload: dict, sensitive: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scrub_tree(payload, sensitive), indent=2, sort_keys=False) + "\n", encoding="utf-8")
