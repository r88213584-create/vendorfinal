"""Prometheus-compatible metrics endpoint.

Tiny zero-dependency text exposition — we deliberately do not pull in
prometheus_client; the wire format is trivial and keeping dependencies low
is part of the product thesis (self-hostable on a $10/mo VPS).
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

_COUNTERS: dict[str, float] = defaultdict(float)
_GAUGES: dict[str, float] = {}
_LABEL_COUNTERS: dict[tuple[str, frozenset[tuple[str, str]]], float] = defaultdict(float)

_STARTED_AT = time.time()


def inc(name: str, value: float = 1.0, **labels: str) -> None:
    if labels:
        key = (name, frozenset(labels.items()))
        _LABEL_COUNTERS[key] += value
    else:
        _COUNTERS[name] += value


def gauge(name: str, value: float) -> None:
    _GAUGES[name] = value


def _fmt_labels(labels: frozenset[tuple[str, str]]) -> str:
    if not labels:
        return ""
    parts = [f'{k}="{v}"' for k, v in sorted(labels)]
    return "{" + ",".join(parts) + "}"


def snapshot(extra_gauges: dict[str, float] | None = None) -> str:
    lines: list[str] = []
    lines.append("# HELP vendorguard_process_uptime_seconds Seconds since app start.")
    lines.append("# TYPE vendorguard_process_uptime_seconds gauge")
    lines.append(f"vendorguard_process_uptime_seconds {time.time() - _STARTED_AT:.2f}")

    for name, value in _COUNTERS.items():
        lines.append(f"# TYPE {name} counter")
        lines.append(f"{name} {value}")

    for (name, labels), value in _LABEL_COUNTERS.items():
        lines.append(f"# TYPE {name} counter")
        lines.append(f"{name}{_fmt_labels(labels)} {value}")

    for name, value in _GAUGES.items():
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")

    for name, value in (extra_gauges or {}).items():
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")

    return "\n".join(lines) + "\n"
