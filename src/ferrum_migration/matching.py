"""Match-set algebra used for fail-closed precedence analysis.

Host lists: ``[]`` means "any host" (Ferrum catch-all tier); ``None`` means
"unknown host set" (the source used something unrepresentable), which can only
collide with catch-all routes because Ferrum always prefers exact and wildcard
host tiers over catch-all routes.

Path spaces use *string-prefix* semantics, a superset of Ferrum's
segment-boundary prefix matching, so overlap answers are conservative.
"""

from __future__ import annotations

from . import util


def host_cover(outer: str, inner: str) -> bool:
    if outer == inner:
        return True
    if outer.startswith("*."):
        suffix = outer[1:]
        if inner.startswith("*."):
            return inner[1:].endswith(suffix)
        return inner.endswith(suffix) and len(inner) > len(suffix)
    return False


def host_overlap(a: str, b: str) -> bool:
    return host_cover(a, b) or host_cover(b, a)


def hosts_overlap(a: list[str] | None, b: list[str] | None) -> bool:
    if a is None and b is None:
        return True
    if a is None:
        return b == []
    if b is None:
        return a == []
    if not a or not b:
        return True
    return any(host_overlap(x, y) for x in a for y in b)


def hosts_cover(outer: list[str] | None, inner: list[str] | None) -> bool:
    if outer is None or inner is None:
        return False
    if not outer:
        return True
    if not inner:
        return False
    return all(any(host_cover(o, i) for o in outer) for i in inner)


def single_host_tier(host: str) -> int:
    """Ferrum router tier for one normalized host entry: 0 = exact, 1 = wildcard."""
    return 1 if host.startswith("*.") else 0


def host_tier(hosts: list[str] | None) -> int:
    if not hosts:
        return 2
    return 1 if any(host.startswith("*.") for host in hosts) else 0


def _witness_tier(hosts: list[str], witness: str) -> tuple[int, int] | None:
    """How ``hosts`` matches ``witness`` in Ferrum's router: ``(tier, wildcard_len)`` or ``None``.

    Tier 0 = exact host, 1 = longest covering wildcard (pattern length descending in ``router_cache.rs``),
    2 = catch-all (empty ``hosts``).
    """
    if not hosts:
        return (2, 0)
    if not witness.startswith("*.") and witness in hosts:
        return (0, 0)
    matched = [h for h in hosts if h.startswith("*.") and host_cover(h, witness)]
    if matched:
        return (1, max(len(h) for h in matched))
    return None


def _overlapping_witness_tiers(a: list[str] | None, b: list[str] | None) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    """Realizable ``((tier_a, wc_len_a), (tier_b, wc_len_b))`` pairs across all concrete overlapping hostnames.

    Evaluated per witness in ``a ∪ b`` (rather than entry-pair Cartesian product) so impossible pairs such as
    ``(0, 1)`` between identical mixed lists ``["api.example.com", "*.example.com"]`` are never fabricated.
    """
    if a is None or b is None:
        return []
    if not a and not b:
        return [((2, 0), (2, 0))]
    witnesses: list[str] = []
    for entry in (a or []) + (b or []):
        if entry not in witnesses:
            witnesses.append(entry)
    result: list[tuple[tuple[int, int], tuple[int, int]]] = []
    for witness in witnesses:
        ma = _witness_tier(a, witness)
        mb = _witness_tier(b, witness)
        if ma is not None and mb is not None:
            result.append((ma, mb))
    return result


def overlapping_tier_pairs(a: list[str] | None, b: list[str] | None) -> set[tuple[int, int]]:
    """All realizable ``(tier_a, tier_b)`` pairs under which Ferrum evaluates ``a`` and ``b`` for one hostname."""
    return {(ma[0], mb[0]) for ma, mb in _overlapping_witness_tiers(a, b)}


def path_space(kind: str, path: str | None) -> tuple[str, bool] | None:
    """``(literal_prefix, exact)``; ``None`` means any path."""
    if kind == "hostonly" or path is None:
        return None
    if kind == "exact":
        return (path, True)
    if kind == "regex":
        return (util.regex_literal_prefix(path), False)
    return (path, False)


def spaces_overlap(a: tuple[str, bool] | None, b: tuple[str, bool] | None) -> bool:
    if a is None or b is None:
        return True
    (pa, ea), (pb, eb) = a, b
    if ea and eb:
        return pa == pb
    if ea:
        return pa.startswith(pb)
    if eb:
        return pb.startswith(pa)
    return pa.startswith(pb) or pb.startswith(pa)


def space_covers(outer_kind: str, outer_path: str | None, inner_kind: str, inner_path: str | None,
                 outer_segment: bool = False, inner_segment: bool = False) -> bool:
    """Whether every path matched by the inner space is matched by the outer one (definitive, not conservative).

    ``outer_segment``/``inner_segment`` mark prefixes with segment semantics (Envoy ``path_separated_prefix``):
    ``/api`` then matches ``/api`` and ``/api/...`` but not ``/apix``. Without it a prefix is a plain string prefix.
    """
    if outer_kind == "hostonly":
        return True
    if outer_kind == "prefix" and outer_path is not None:
        if inner_kind == "hostonly":
            return outer_path == "/"
        if outer_segment:
            base = outer_path.rstrip("/")
            if not base:
                return True  # a segment prefix of "/" matches every path

            def under(path: str, may_equal: bool) -> bool:
                return path.startswith(base + "/") or (may_equal and path == base)

            if inner_kind == "exact" and inner_path is not None:
                return under(inner_path, True)
            if inner_kind == "prefix" and inner_path is not None:
                # A string-prefix inner /api also matches /apix, which a segment /api does not.
                return under(inner_path, inner_segment)
            if inner_kind == "regex" and inner_path is not None:
                return under(util.regex_literal_prefix(inner_path), False)
            return False
        if inner_kind in ("prefix", "exact") and inner_path is not None:
            return inner_path.startswith(outer_path)
        if inner_kind == "regex" and inner_path is not None:
            return util.regex_literal_prefix(inner_path).startswith(outer_path)
        return False
    if outer_kind in ("exact", "regex"):
        return inner_kind == outer_kind and inner_path == outer_path
    return False


def methods_overlap(a: list[str] | None, b: list[str] | None) -> bool:
    if a is None or b is None:
        return True
    return bool(set(a) & set(b))


def methods_cover(outer: list[str] | None, inner: list[str] | None) -> bool:
    if outer is None:
        return True
    if inner is None:
        return False
    return set(inner) <= set(outer)


def ports_compatible(a: int | None, b: int | None) -> bool:
    return a is None or b is None or a == b


def path_rank(kind: str, path: str | None) -> tuple[int, int]:
    """Lower sorts first = Ferrum prefers it within one host tier."""
    if kind == "exact":
        return (0, 0)
    if kind == "prefix":
        return (1, -len(path or ""))
    if kind == "regex":
        return (2, 0)
    return (3, 0)


def _case_insensitive(route) -> bool:
    return bool(getattr(route, "case_insensitive", False))


def _fold(path):
    """Case-fold a literal path. Emitted listen paths are ASCII (canonical-path check), so lower() keeps lengths.

    Translators may compare paths before the emitter validated them; anything that is not a string is returned
    unchanged (it is refused later as not representable).
    """
    return path.lower() if isinstance(path, str) else path


def _fold_space(space: tuple[str, bool] | None) -> tuple[str, bool] | None:
    return None if space is None else (_fold(space[0]), space[1])


def _has_letters(text: str) -> bool:
    return text.lower() != text.upper()


def route_overlaps(a, b) -> bool:
    """Whether two RouteSpecs could match one request (conservative).

    When either side matched case-insensitively in the source, the comparison is made on case-folded paths
    (a superset of both match sets) and the segment/exact disjointness proof is not applied: it was derived for
    case-sensitive matching only.
    """
    if not ports_compatible(a.listen_port, b.listen_port):
        return False
    if not hosts_overlap(a.hosts, b.hosts):
        return False
    if not methods_overlap(a.methods, b.methods):
        return False
    folded = _case_insensitive(a) or _case_insensitive(b)
    if a.path_ok and b.path_ok and not folded and _segment_exact_disjoint(a, b):
        return False
    space_a = None if not a.path_ok else path_space(a.kind, a.path)
    space_b = None if not b.path_ok else path_space(b.kind, b.path)
    if folded:
        space_a, space_b = _fold_space(space_a), _fold_space(space_b)
    return spaces_overlap(space_a, space_b)


def receives_case_variants(source, other) -> bool:
    """Whether ``other`` can match a request that only the case-insensitive ``source`` matched in the source.

    Such a request is a case variant of ``source``'s literal path (``/API`` for ``/api``). Ferrum matches paths
    case-sensitively, so the emitted ``source`` route never receives it, and any other route matching it would
    forward traffic the source sent to ``source``. Definitive only where it answers False; every unknown shape
    answers True (fail closed). Host tiers are not considered here.
    """
    if not ports_compatible(source.listen_port, other.listen_port):
        return False
    if not hosts_overlap(source.hosts, other.hosts) or not methods_overlap(source.methods, other.methods):
        return False
    if not source.path_ok or source.kind not in ("prefix", "exact") or not isinstance(source.path, str):
        return True
    p, p_exact = source.path, source.kind == "exact"
    if not _has_letters(p):
        return False  # a literal without letters has no case variants
    if not other.path_ok or other.kind == "hostonly" or not isinstance(other.path, str):
        return True
    if other.kind == "regex":
        # A top-level alternation has no literal prefix shared by every branch: the first branch's literal says
        # nothing about the others, so whether it intersects the variants is unknown (fail closed). Any pipe the
        # shared narrow-grammar proof cannot place inside a group counts as such.
        if util.regex_alternation_unproven(other.path):
            return True
        # Every regex match starts with its literal prefix; the rest of the pattern may match any case.
        q, q_exact = util.regex_literal_prefix(other.path), False
    elif other.kind in ("prefix", "exact"):
        q, q_exact = other.path, other.kind == "exact"
    else:
        return True
    # String-prefix envelopes (a superset of segment semantics) on folded paths must intersect at all.
    if not spaces_overlap((p.lower(), p_exact), (q.lower(), q_exact)):
        return False
    shared = min(len(p), len(q))
    if p[:shared] != q[:shared]:
        return True  # other's literal is itself a case variant within the shared part
    if len(q) >= len(p):
        return False  # everything other matches starts with source's exact-case literal: no variant
    # other's literal is a proper literal prefix of source's: it matches source's variants when the rest of
    # source's literal has letters whose case can differ.
    return _has_letters(p[len(q):])


def _segment_exact_disjoint(a, b) -> bool:
    """A segment prefix (Envoy ``path_separated_prefix``, Istio route-semantics prefixes) and a literal route it
    provably never shares a request with.

    ``/api`` with segment semantics matches ``/api`` and ``/api/...`` only, in the source and in Ferrum alike.
    It is disjoint from an exact ``/apix`` (or ``/ap``), from another segment prefix ``/apix`` (neither is a
    segment ancestor of the other), and from a string prefix ``/apix`` (every path it matches starts with
    ``/apix``, which is neither ``/api`` nor under ``/api/``). Any other pair keeps the conservative string check.
    """
    for seg, other in ((a, b), (b, a)):
        if seg.kind != "prefix" or getattr(seg, "prefix_semantics", "string") != "segment":
            continue
        if other.kind not in ("exact", "prefix"):
            continue
        if not isinstance(seg.path, str) or not isinstance(other.path, str):
            return False
        base = seg.path.rstrip("/")
        if not base:
            return False  # a segment prefix of "/" matches every path

        def under(path: str) -> bool:
            return path == base or path.startswith(base + "/")

        if other.kind == "exact":
            return not under(other.path)
        if getattr(other, "prefix_semantics", "string") == "segment":
            other_base = other.path.rstrip("/")
            if not other_base:
                return False
            return not (under(other_base) or base == other_base or base.startswith(other_base + "/"))
        # A string prefix q: disjoint when q extends base inside one segment (/apix), or diverges from it.
        q = other.path
        if q.startswith(base):
            return not under(q) and not q.startswith(base + "/") and len(q) > len(base) and q[len(base)] != "/"
        return not base.startswith(q)
    return False


def route_covers(outer, inner) -> bool:
    """Whether every request matching ``inner`` also matches unconditional ``outer``."""
    if outer.extra_conditions or not outer.path_ok or not inner.path_ok:
        return False
    if not ports_compatible(outer.listen_port, inner.listen_port) or (
            outer.listen_port is not None and outer.listen_port != inner.listen_port):
        return False
    outer_path, inner_path = outer.path, inner.path
    if _case_insensitive(inner) or _case_insensitive(outer):
        if _case_insensitive(inner) and not _case_insensitive(outer):
            # A case-sensitive route only matches every case variant of the inner route when its own literal
            # has no letters (or it is host-only).
            if outer.kind != "hostonly" and not (outer.kind == "prefix" and isinstance(outer_path, str)
                                                  and not _has_letters(outer_path)):
                return False
        outer_path, inner_path = _fold(outer_path), _fold(inner_path)
    return (hosts_cover(outer.hosts, inner.hosts)
            and methods_cover(outer.methods, inner.methods)
            and space_covers(outer.kind, outer_path, inner.kind, inner_path,
                             outer_segment=getattr(outer, "prefix_semantics", "string") == "segment",
                             inner_segment=getattr(inner, "prefix_semantics", "string") == "segment"))


def ferrum_prefers(a, b) -> bool | None:
    """True if Ferrum picks ``a`` over ``b`` for every overlapping request; False if ``b``; None if unclear.

    Mirrors ``router_cache.rs``: exact host (tier 0) > wildcard host (tier 1) > catch-all (tier 2). Within each
    tier, exact path > prefix > regex > host-only; within the wildcard tier's same path class, Ferrum scans
    wildcard patterns by length descending (e.g. ``*.sub.example.test`` before ``*.example.test``) before
    comparing prefix lengths. Definite only when every realizable overlapping witness resolves to one winner.
    """
    pairs = _overlapping_witness_tiers(a.hosts, b.hosts)
    if not pairs:
        return None
    class_a, sub_a = path_rank(a.kind, a.path)
    class_b, sub_b = path_rank(b.kind, b.path)
    verdicts: set[bool] = set()
    for (tier_a, wc_a), (tier_b, wc_b) in pairs:
        if tier_a != tier_b:
            verdicts.add(tier_a < tier_b)
        elif class_a != class_b:
            verdicts.add(class_a < class_b)
        elif tier_a == 1 and wc_a != wc_b:
            verdicts.add(wc_a > wc_b)
        elif sub_a != sub_b:
            verdicts.add(sub_a < sub_b)
        else:
            return None
    return next(iter(verdicts)) if len(verdicts) == 1 else None
