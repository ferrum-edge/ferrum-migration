"""Fixture case model and strict loader.

A case is one synthetic source configuration plus the requests that pin its
source-product semantics. Every positive probe states exactly which loopback
backend must receive the request and with which request-target; every deny
probe states that *no* backend may receive it. Unknown keys are errors so a
typo cannot silently weaken an assertion.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .util import source_placeholders

ADAPTERS = ("kong-dbless", "kong-deck", "nginx", "traefik", "envoy", "istio", "selftest")
BACKEND_TAGS = ("a", "b")
SOURCE_PLACEHOLDERS = {"ECHO_A_PORT", "ECHO_B_PORT", "LISTEN_PORT", "WORKDIR", "CANARY_KEY", "CANARY_HASH"}
HEADER_PLACEHOLDERS = {"CANARY_KEY", "WRONG_KEY", "BASIC_HASH_AS_PASSWORD"}
CANARY_NAMES = {"CANARY_KEY", "CANARY_HASH"}

_CASE_KEYS = {
    "id", "adapter", "title", "source", "include_secrets", "allow_rejection", "claims",
    "not_claimed", "not_established", "source_semantics", "backend_host_rewrite", "probes",
    "report", "secret_free", "mesh_policy", "converter_assertions",
}
# Names of operator assertions a case may pass to the converter (the profile maps each to argv). A case names one
# only when its synthetic source is known to satisfy it.
_ASSERTION_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_PROBE_KEYS = {"id", "method", "path", "host", "headers", "expect", "ferrum_only", "note"}
_EXPECT_KEYS = {"forward", "deny", "status"}
_FORWARD_KEYS = {"backend", "path"}
_REPORT_KEYS = {"min_errors", "min_findings", "mentions_any"}


class CaseError(ValueError):
    pass


@dataclass
class Probe:
    id: str
    method: str
    path: str
    host: str
    headers: dict[str, str]
    forward_backend: "str | None"
    forward_path: "str | None"
    deny: bool
    statuses: list[int]
    ferrum_only: bool
    note: str

    @property
    def positive(self) -> bool:
        return self.forward_backend is not None


@dataclass
class Case:
    id: str
    adapter: str
    title: str
    directory: Path
    source: Path
    include_secrets: bool
    allow_rejection: bool
    claims: list[str]
    not_claimed: list[str]
    not_established: list[str]
    source_semantics: str
    backend_host_rewrite: dict[str, str]
    probes: list[Probe]
    report_min_errors: int
    report_min_findings: int
    report_mentions_any: list[str]
    secret_free: list[str]
    mesh_policy: bool = False
    #: Operator assertions passed to the converter (profile ``assertion_argv``), e.g.
    #: ``traefik-entrypoints-add-no-controls``. Never implied: absent means the converter's default.
    converter_assertions: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    @property
    def deny_only(self) -> bool:
        return all(not p.positive for p in self.probes)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise CaseError(msg)


def _str_list(value, what: str) -> list[str]:
    _require(isinstance(value, list) and all(isinstance(v, str) for v in value), f"{what} must be a list of strings")
    return list(value)


def _load_probe(raw: dict, case_id: str) -> Probe:
    _require(isinstance(raw, dict), f"{case_id}: probe must be an object")
    unknown = set(raw) - _PROBE_KEYS
    _require(not unknown, f"{case_id}: probe has unknown keys {sorted(unknown)}")
    pid = raw.get("id")
    _require(isinstance(pid, str) and pid, f"{case_id}: probe needs an id")
    path = raw.get("path")
    _require(isinstance(path, str) and path.startswith("/"), f"{case_id}/{pid}: path must start with /")
    host = raw.get("host", "app.example.test")
    _require(isinstance(host, str) and host, f"{case_id}/{pid}: host must be a string")
    method = str(raw.get("method", "GET")).upper()
    headers = raw.get("headers", {})
    _require(isinstance(headers, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()),
             f"{case_id}/{pid}: headers must map strings to strings")
    for value in headers.values():
        unknown_ph = source_placeholders(value) - HEADER_PLACEHOLDERS
        _require(not unknown_ph, f"{case_id}/{pid}: unknown header placeholder(s) {sorted(unknown_ph)}")
    expect = raw.get("expect")
    _require(isinstance(expect, dict), f"{case_id}/{pid}: expect is required")
    unknown = set(expect) - _EXPECT_KEYS
    _require(not unknown, f"{case_id}/{pid}: expect has unknown keys {sorted(unknown)}")
    forward = expect.get("forward")
    deny = bool(expect.get("deny", False))
    _require((forward is not None) != deny, f"{case_id}/{pid}: expect exactly one of forward/deny")
    statuses = expect.get("status")
    if forward is not None:
        _require(isinstance(forward, dict) and not (set(forward) - _FORWARD_KEYS), f"{case_id}/{pid}: bad forward block")
        backend = forward.get("backend")
        _require(backend in BACKEND_TAGS, f"{case_id}/{pid}: forward.backend must be one of {BACKEND_TAGS}")
        fpath = forward.get("path")
        _require(isinstance(fpath, str) and fpath.startswith("/"), f"{case_id}/{pid}: forward.path must start with /")
        if statuses is None:
            statuses = [200]
    else:
        backend, fpath = None, None
        _require(statuses is not None, f"{case_id}/{pid}: deny probes must list acceptable statuses")
    if isinstance(statuses, int):
        statuses = [statuses]
    _require(isinstance(statuses, list) and statuses and all(isinstance(s, int) for s in statuses),
             f"{case_id}/{pid}: status must be an int or list of ints")
    return Probe(
        id=pid, method=method, path=path, host=host, headers=dict(headers),
        forward_backend=backend, forward_path=fpath, deny=deny, statuses=list(statuses),
        ferrum_only=bool(raw.get("ferrum_only", False)), note=str(raw.get("note", "")),
    )


def load_case(directory: Path) -> Case:
    path = directory / "case.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CaseError(f"{directory.name}: cannot read case.json ({type(exc).__name__})") from None
    _require(isinstance(raw, dict), f"{directory.name}: case.json must be an object")
    unknown = set(raw) - _CASE_KEYS
    _require(not unknown, f"{directory.name}: unknown keys {sorted(unknown)}")
    cid = raw.get("id")
    _require(cid == directory.name, f"{directory.name}: id must equal the directory name")
    adapter = raw.get("adapter")
    _require(adapter in ADAPTERS, f"{cid}: adapter must be one of {ADAPTERS}")
    source_name = raw.get("source")
    _require(isinstance(source_name, str) and "/" not in source_name and source_name not in ("", ".", ".."),
             f"{cid}: source must be a plain filename")
    source = directory / source_name
    _require(source.is_file(), f"{cid}: source file {source_name} missing")
    text = source.read_text(encoding="utf-8")
    unknown_ph = source_placeholders(text) - SOURCE_PLACEHOLDERS
    _require(not unknown_ph, f"{cid}: unknown source placeholder(s) {sorted(unknown_ph)}")
    probes_raw = raw.get("probes")
    _require(isinstance(probes_raw, list) and probes_raw, f"{cid}: probes must be a non-empty list")
    probes = [_load_probe(p, cid) for p in probes_raw]
    ids = [p.id for p in probes]
    _require(len(ids) == len(set(ids)), f"{cid}: probe ids must be unique")
    report = raw.get("report", {})
    _require(isinstance(report, dict) and not (set(report) - _REPORT_KEYS), f"{cid}: bad report block")
    secret_free = _str_list(raw.get("secret_free", []), f"{cid}: secret_free")
    _require(set(secret_free) <= CANARY_NAMES, f"{cid}: secret_free may only name {sorted(CANARY_NAMES)}")
    rewrite = raw.get("backend_host_rewrite", {})
    _require(isinstance(rewrite, dict) and all(isinstance(k, str) and v == "127.0.0.1" for k, v in rewrite.items()),
             f"{cid}: backend_host_rewrite may only map synthetic names to 127.0.0.1")
    for key in rewrite:
        _require(key.endswith(".svc.cluster.local") and key.startswith("acc-"),
                 f"{cid}: backend_host_rewrite keys must be synthetic acc-*.svc.cluster.local names")
    claims = _str_list(raw.get("claims", []), f"{cid}: claims")
    _require(bool(claims), f"{cid}: at least one claim is required")
    semantics = raw.get("source_semantics")
    _require(isinstance(semantics, str) and semantics, f"{cid}: source_semantics is required")
    title = raw.get("title")
    _require(isinstance(title, str) and title, f"{cid}: title is required")
    assertions = _str_list(raw.get("converter_assertions", []), f"{cid}: converter_assertions")
    _require(all(_ASSERTION_NAME.match(name) for name in assertions) and len(assertions) == len(set(assertions)),
             f"{cid}: converter_assertions must be unique lower-case names")
    return Case(
        id=cid, adapter=adapter, title=title, directory=directory, source=source,
        include_secrets=bool(raw.get("include_secrets", False)),
        allow_rejection=bool(raw.get("allow_rejection", False)),
        claims=claims,
        not_claimed=_str_list(raw.get("not_claimed", []), f"{cid}: not_claimed"),
        not_established=_str_list(raw.get("not_established", []), f"{cid}: not_established"),
        source_semantics=semantics,
        backend_host_rewrite=dict(rewrite),
        probes=probes,
        report_min_errors=int(report.get("min_errors", 0)),
        report_min_findings=int(report.get("min_findings", 0)),
        report_mentions_any=_str_list(report.get("mentions_any", []), f"{cid}: report.mentions_any"),
        secret_free=secret_free,
        mesh_policy=bool(raw.get("mesh_policy", False)),
        converter_assertions=assertions,
    )


def load_cases(fixtures_dir: Path) -> list[Case]:
    if not fixtures_dir.is_dir():
        raise CaseError(f"fixtures directory not found: {fixtures_dir}")
    cases = []
    for child in sorted(fixtures_dir.iterdir()):
        if child.is_dir() and (child / "case.json").is_file():
            cases.append(load_case(child))
    if not cases:
        raise CaseError(f"no cases under {fixtures_dir}")
    return cases
