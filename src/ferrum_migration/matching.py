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


def host_tier(hosts: list[str] | None) -> int:
    if not hosts:
        return 2
    return 1 if any(host.startswith("*.") for host in hosts) else 0


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


def route_overlaps(a, b) -> bool:
    """Whether two RouteSpecs could match one request (conservative)."""
    if not ports_compatible(a.listen_port, b.listen_port):
        return False
    if not hosts_overlap(a.hosts, b.hosts):
        return False
    if not methods_overlap(a.methods, b.methods):
        return False
    space_a = None if not a.path_ok else path_space(a.kind, a.path)
    space_b = None if not b.path_ok else path_space(b.kind, b.path)
    return spaces_overlap(space_a, space_b)


def route_covers(outer, inner) -> bool:
    """Whether every request matching ``inner`` also matches unconditional ``outer``."""
    if outer.extra_conditions or not outer.path_ok or not inner.path_ok:
        return False
    if not ports_compatible(outer.listen_port, inner.listen_port) or (
            outer.listen_port is not None and outer.listen_port != inner.listen_port):
        return False
    return (hosts_cover(outer.hosts, inner.hosts)
            and methods_cover(outer.methods, inner.methods)
            and space_covers(outer.kind, outer.path, inner.kind, inner.path,
                             outer_segment=getattr(outer, "prefix_semantics", "string") == "segment",
                             inner_segment=getattr(inner, "prefix_semantics", "string") == "segment"))


def ferrum_prefers(a, b) -> bool | None:
    """True if Ferrum picks ``a`` over ``b`` for requests matching both; None if unclear."""
    tier_a, tier_b = host_tier(a.hosts), host_tier(b.hosts)
    if tier_a != tier_b:
        return tier_a < tier_b
    rank_a, rank_b = path_rank(a.kind, a.path), path_rank(b.kind, b.path)
    if rank_a != rank_b:
        return rank_a < rank_b
    return None
