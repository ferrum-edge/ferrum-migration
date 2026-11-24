"""Migration report: every caveat, refusal and safe omission, in stable order."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import FERRUM_EDGE_REFERENCE_COMMIT, __version__
from .redact import safe_label

SEVERITIES = ("error", "warning", "info")
_RANK = {name: index for index, name in enumerate(SEVERITIES)}

SEVERITY_MEANING = {
    "error": "review required before use: something was refused, emitted fail-closed, "
    "or behaves less strictly than the source in a way the tool could not prevent",
    "warning": "behavior differs from the source but is not less secure (usually stricter or approximate)",
    "info": "safely omitted metadata or an informational note",
}


@dataclass(frozen=True)
class Caveat:
    severity: str
    code: str
    ref: str
    message: str
    action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "severity": self.severity,
            "code": self.code,
            "source": self.ref,
            "message": self.message,
        }
        if self.action:
            data["action"] = self.action
        return data


class Report:
    """Collects caveats. Messages must never contain credential values."""

    def __init__(self, platform: str, input_label: str) -> None:
        self.platform = platform
        self.input_label = safe_label(input_label, 120)
        self._items: list[Caveat] = []
        self._seen: set[tuple[str, str, str, str]] = set()

    def add(self, severity: str, code: str, ref: str, message: str, action: str | None = None) -> None:
        if severity not in _RANK:
            raise ValueError(f"unknown severity {severity!r}")
        item = Caveat(severity, code, ref or "-", message, action)
        key = (severity, code, item.ref, message)
        if key in self._seen:
            return
        self._seen.add(key)
        self._items.append(item)

    def error(self, code: str, ref: str, message: str, action: str | None = None) -> None:
        self.add("error", code, ref, message, action)

    def warning(self, code: str, ref: str, message: str, action: str | None = None) -> None:
        self.add("warning", code, ref, message, action)

    def info(self, code: str, ref: str, message: str, action: str | None = None) -> None:
        self.add("info", code, ref, message, action)

    @property
    def caveats(self) -> list[Caveat]:
        return list(self._items)

    def count(self, severity: str) -> int:
        return sum(1 for item in self._items if item.severity == severity)

    @property
    def has_errors(self) -> bool:
        return self.count("error") > 0

    @property
    def has_warnings(self) -> bool:
        return self.count("warning") > 0

    def ordered(self) -> list[Caveat]:
        indexed = list(enumerate(self._items))
        indexed.sort(key=lambda pair: (_RANK[pair[1].severity], pair[0]))
        return [item for _, item in indexed]

    def to_json_obj(self, summary: dict[str, Any], next_steps: list[str]) -> dict[str, Any]:
        return {
            "tool": "ferrum-migration",
            "tool_version": __version__,
            "ferrum_edge_reference_commit": FERRUM_EDGE_REFERENCE_COMMIT,
            "platform": self.platform,
            "input": self.input_label,
            "summary": summary,
            "counts": {severity: self.count(severity) for severity in SEVERITIES},
            "severity_meaning": dict(SEVERITY_MEANING),
            "next_steps": list(next_steps),
            "caveats": [item.to_dict() for item in self.ordered()],
        }

    def to_markdown(self, summary: dict[str, Any], next_steps: list[str]) -> str:
        lines = [
            "# Ferrum Edge migration report",
            "",
            f"- Source platform: `{self.platform}`",
            f"- Input: `{_md(self.input_label)}`",
            f"- Tool: ferrum-migration {__version__} (mappings verified against Ferrum Edge "
            f"`{FERRUM_EDGE_REFERENCE_COMMIT[:12]}`)",
            "",
            "This report never contains credential values. Review every error before using the output.",
            "",
            "## Summary",
            "",
            "| Item | Value |",
            "|---|---|",
        ]
        for key, value in summary.items():
            lines.append(f"| {key} | {_md(str(value))} |")
        lines.append(
            f"| caveats | {self.count('error')} error, {self.count('warning')} warning, {self.count('info')} info |"
        )
        lines += ["", "## Next steps", ""]
        lines += [f"{index}. {_md(step)}" for index, step in enumerate(next_steps, start=1)]
        for severity in SEVERITIES:
            items = [item for item in self.ordered() if item.severity == severity]
            lines += ["", f"## {severity.capitalize()} ({len(items)})", "", f"_{SEVERITY_MEANING[severity]}_", ""]
            if not items:
                lines.append("None.")
            for item in items:
                entry = f"- **{item.code}** (`{_md(item.ref)}`): {_md(item.message)}"
                if item.action:
                    entry += f" _Action:_ {_md(item.action)}"
                lines.append(entry)
        return "\n".join(lines) + "\n"


def _md(text: str) -> str:
    return text.replace("`", "'").replace("|", "\\|").replace("\n", " ")
