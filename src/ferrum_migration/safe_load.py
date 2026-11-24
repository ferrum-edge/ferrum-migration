"""Bounded, fail-closed loading of YAML, JSON and TOML input.

* Reads at most ``max_input_bytes + 1`` bytes from one regular file (or stdin).
* Rejects NUL bytes and invalid UTF-8.
* YAML: safe constructors only, duplicate mapping keys rejected, merge keys
  (``<<``) rejected, ``!!binary``/``!!set``/``!!omap``/``!!pairs`` rejected,
  timestamps kept as strings, alias count and composed node count bounded,
  multiple documents only where the platform supports them.
* JSON: duplicate keys and NaN/Infinity rejected.
* TOML: duplicate keys rejected by the parser; date/time values become strings.
* Every decoded tree is walked once with a visit budget (shared YAML aliases are
  counted on every visit, defeating alias expansion bombs), a depth limit and a
  string-size limit.
* Diagnostics carry positions and generic reasons only; quoted spans that might
  echo document content are withheld.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import stat
import sys
import tomllib
from typing import Any

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

from .errors import InputError
from .limits import Limits
from .redact import sanitize_parser_message


def read_input(path: str, limits: Limits) -> str:
    if path == "-":
        data = sys.stdin.buffer.read(limits.max_input_bytes + 1)
    else:
        try:
            info = os.stat(path)
        except OSError:
            raise InputError("input file cannot be read") from None
        if not stat.S_ISREG(info.st_mode):
            raise InputError("input must be a regular file")
        try:
            with open(path, "rb") as handle:
                data = handle.read(limits.max_input_bytes + 1)
        except OSError:
            raise InputError("input file cannot be read") from None
    if len(data) > limits.max_input_bytes:
        raise InputError(f"input exceeds the {limits.max_input_bytes}-byte limit")
    if b"\x00" in data:
        raise InputError("input contains NUL bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(f"input is not valid UTF-8 (byte offset {exc.start})") from None
    if text.startswith("﻿"):
        text = text[1:]
    return text


class _BoundedLoader(yaml.SafeLoader):
    """SafeLoader with alias/node budgets, duplicate-key and merge-key rejection."""

    _limits: Limits = Limits()
    _aliases = 0
    _nodes = 0

    def compose_node(self, parent, index):  # noqa: D401 - PyYAML hook
        if self.check_event(AliasEvent):
            self._aliases += 1
            if self._aliases > self._limits.max_aliases:
                mark = self.peek_event().start_mark
                raise InputError(
                    f"YAML alias limit ({self._limits.max_aliases}) exceeded at line {mark.line + 1}")
        else:
            self._nodes += 1
            if self._nodes > self._limits.max_nodes:
                raise InputError(f"YAML input exceeds the {self._limits.max_nodes}-node limit")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        if isinstance(node, MappingNode):
            seen = set()
            for key_node, _value_node in node.value:
                line = key_node.start_mark.line + 1
                column = key_node.start_mark.column + 1
                if key_node.tag == "tag:yaml.org,2002:merge":
                    raise InputError(f"YAML merge keys ('<<') are not supported (line {line})")
                key = self.construct_object(key_node, deep=True)
                try:
                    hash(key)
                except TypeError:
                    raise InputError(f"unhashable YAML mapping key at line {line}") from None
                if key in seen:
                    raise InputError(f"duplicate YAML mapping key at line {line}, column {column}")
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _reject_tag(loader, node):
    raise InputError(f"unsupported YAML tag at line {node.start_mark.line + 1}")


for _tag in ("tag:yaml.org,2002:binary", "tag:yaml.org,2002:set",
             "tag:yaml.org,2002:omap", "tag:yaml.org,2002:pairs"):
    _BoundedLoader.add_constructor(_tag, _reject_tag)
_BoundedLoader.add_constructor("tag:yaml.org,2002:timestamp",
                               lambda loader, node: loader.construct_scalar(node))


def load_yaml(text: str, limits: Limits, allow_multi: bool) -> list[Any]:
    loader = _BoundedLoader(text)
    loader._limits = limits
    loader._aliases = 0
    loader._nodes = 0
    documents: list[Any] = []
    try:
        while loader.check_data():
            document = loader.get_data()
            if document is None:
                continue
            documents.append(document)
            if len(documents) > limits.max_documents:
                raise InputError(f"more than {limits.max_documents} YAML documents")
            if not allow_multi and len(documents) > 1:
                raise InputError("multiple YAML documents are not supported for this platform; "
                                 "pass a single document")
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark or exc.context_mark
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise InputError(f"YAML syntax error{where}: {sanitize_parser_message(exc.problem)}") from None
    except yaml.YAMLError:
        raise InputError("invalid YAML") from None
    except RecursionError:
        raise InputError("YAML nesting is too deep") from None
    finally:
        loader.dispose()
    return documents


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON object key")
        result[key] = value
    return result


def _json_constant(_name):
    raise InputError("JSON NaN/Infinity values are not supported")


def load_json(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_json_constant)
    except json.JSONDecodeError as exc:
        raise InputError(
            f"JSON syntax error at line {exc.lineno}, column {exc.colno}: {sanitize_parser_message(exc.msg)}"
        ) from None
    except RecursionError:
        raise InputError("JSON nesting is too deep") from None


def load_toml(text: str) -> Any:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise InputError(f"TOML syntax error: {sanitize_parser_message(str(exc))}") from None
    except RecursionError:
        raise InputError("TOML nesting is too deep") from None


def _check_string(text: str, limit: int, what: str) -> None:
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        raise InputError(f"{what} contains lone Unicode surrogates") from None
    if len(encoded) > limit:
        raise InputError(f"{what} exceeds the string-size limit")


def check_tree(obj: Any, limits: Limits) -> Any:
    """Enforce visit/depth/string budgets and normalize date/time values to strings."""
    visits = 0

    def normalize(value: Any) -> Any:
        if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
            return value.isoformat()
        return value

    root = normalize(obj)
    stack: list[tuple[Any, int]] = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        visits += 1
        if visits > limits.max_nodes:
            raise InputError(f"input exceeds the {limits.max_nodes}-node limit (after alias expansion)")
        if depth > limits.max_depth:
            raise InputError(f"input nesting exceeds depth {limits.max_depth}")
        if isinstance(node, dict):
            for key in list(node.keys()):
                if isinstance(key, str):
                    _check_string(key, limits.max_string_bytes, "a mapping key")
                value = normalize(node[key])
                if value is not node[key]:
                    node[key] = value
                stack.append((value, depth + 1))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                normalized = normalize(value)
                if normalized is not value:
                    node[index] = normalized
                stack.append((normalized, depth + 1))
        elif isinstance(node, str):
            _check_string(node, limits.max_string_bytes, "a string value")
    return root


def load_structured(text: str, fmt: str, limits: Limits, allow_multi: bool = False) -> list[Any]:
    if fmt == "json":
        documents = [load_json(text)]
    elif fmt == "toml":
        documents = [load_toml(text)]
    elif fmt == "yaml":
        documents = load_yaml(text, limits, allow_multi)
    else:
        raise InputError(f"input format {fmt!r} is not supported for this platform")
    return [check_tree(document, limits) for document in documents]
