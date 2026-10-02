# SPDX-License-Identifier: Apache-2.0
# New AI-assisted implementation, 2026-10-02. See ORIGIN.md and LICENSE.
"""Finite, caller-visible limits and sanitized uncertainty codes."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Limits:
    inventory_bytes: int = 524288
    snapshot_bytes: int = 4194304
    depth: int = 32
    nodes: int = 50000
    packages: int = 256
    advisories: int = 512
    affected: int = 64
    ranges: int = 64
    events: int = 256
    versions: int = 4096
    total_versions: int = 8192
    aliases: int = 128
    total_aliases: int = 4096
    comparisons: int = 100000
    report_bytes: int = 4194304

    def __post_init__(self):
        ceilings = (
            524288,
            4194304,
            32,
            50000,
            256,
            512,
            64,
            64,
            256,
            4096,
            8192,
            128,
            4096,
            100000,
            4194304,
        )
        if any(
            type(v) is not int or not 1 <= v <= cap
            for v, cap in zip(asdict(self).values(), ceilings, strict=True)
        ):
            raise ValueError("invalid_limits")
        if self.report_bytes < 4096:
            raise ValueError("invalid_report_budget")


class Rejected(ValueError):
    """Contains only a fixed, safe code: never rejected input text."""


class Work:
    def __init__(self, limits):
        self.limits = limits
        self.used = {"comparisons": 0, "total_versions": 0, "total_aliases": 0}

    def charge(self, field, count=1):
        proposed = self.used[field] + count
        if proposed > getattr(self.limits, field):
            raise Rejected(field + "_budget")
        self.used[field] = proposed


def bounded_list(value, maximum, code):
    if type(value) is not list:
        raise Rejected(code + "_array_required")
    if len(value) > maximum:
        raise Rejected(code + "_budget")
    return value
