"""Resource ceilings applied to every input before and during translation."""

from __future__ import annotations

from dataclasses import dataclass

#: Hard ceiling for ``--max-input-bytes`` so a typo cannot ask for unbounded memory.
ABSOLUTE_MAX_INPUT_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class Limits:
    max_input_bytes: int = 8 * 1024 * 1024
    #: Total structured-node visits (shared YAML aliases count on every visit).
    max_nodes: int = 500_000
    max_depth: int = 64
    max_aliases: int = 64
    max_documents: int = 2_000
    max_string_bytes: int = 1_048_576
    max_routes: int = 20_000
    max_nginx_tokens: int = 1_000_000
    max_nginx_block_depth: int = 32
    #: Pairwise precedence analysis (Traefik priorities) is quadratic.
    max_precedence_routes: int = 4_000
    max_rule_terms: int = 32
