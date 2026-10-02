# SPDX-License-Identifier: Apache-2.0
# New AI-assisted implementation, 2026-10-02. See ORIGIN.md and LICENSE.
"""PEP 440 ordering and OSV numbered-range timeline evaluation.

All limits restrict the WHOLE range; multiple limits are an OR. A limit is
not a fixed event. Events can arrive unsorted. Neither SemVer nor Git ranges
are passed to the PEP 440 comparator.
"""

import re

from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version

from .contracts import Rejected, bounded_list


def package_name(value):
    if type(value) is not str or not 1 <= len(value) <= 128 or not value.isascii():
        raise Rejected("invalid_package_name")
    try:
        return str(canonicalize_name(value, validate=True))
    except InvalidName:
        raise Rejected("invalid_package_name") from None


def version(value):
    if type(value) is not str or not 1 <= len(value) <= 256 or not value.isascii():
        raise Rejected("unknown_or_invalid_version")
    try:
        return Version(value)
    except InvalidVersion:
        raise Rejected("unknown_or_invalid_version") from None


def identifier(value):
    # Deliberately bounded identifier subset; summaries/URLs are never emitted.
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}", value):
        raise Rejected("unsupported_advisory_identifier")
    return value


def prepare_range(obj, limits):
    if type(obj) is not dict:
        raise Rejected("range_object_required")
    if obj.get("type") != "ECOSYSTEM":
        raise Rejected("unsupported_range_type")
    events = bounded_list(obj.get("events"), limits.events, "range_events")
    if not events:
        raise Rejected("empty_range_events")
    timeline, upper_limits, positions = [], [], set()
    kinds = set()
    for event in events:
        if type(event) is not dict or len(event) != 1:
            raise Rejected("invalid_range_event")
        kind, text = next(iter(event.items()))
        if kind not in ("introduced", "fixed", "last_affected", "limit"):
            raise Rejected("unsupported_range_event")
        if type(text) is not str or not 1 <= len(text) <= 256 or not text.isascii():
            raise Rejected("unknown_or_invalid_range_version")
        if kind == "limit":
            upper_limits.append(None if "*" in text else version(text))
            continue
        v = None if kind == "introduced" and text == "0" else version(text)
        if v in positions:
            # Equal-normalized opposing events have no order specified by OSV.
            raise Rejected("ambiguous_or_duplicate_range_boundary")
        positions.add(v)
        kinds.add(kind)
        timeline.append((v, kind))
    if "introduced" not in kinds or {"fixed", "last_affected"} <= kinds:
        raise Rejected("invalid_range_timeline")
    timeline.sort(key=lambda pair: (pair[0] is not None, pair[0] or Version("0")))
    # A closing event before the first introduction is not interpreted as a
    # complete numbered-range declaration. It is conservative OPEN.
    if timeline[0][1] != "introduced":
        raise Rejected("invalid_range_timeline")
    return timeline, upper_limits


def contains(v, prepared, work):
    timeline, upper_limits = prepared
    before_limit = not upper_limits
    for limit in upper_limits:
        work.charge("comparisons")
        if limit is None or v < limit:
            before_limit = True
    if not before_limit:
        return False
    affected = False
    for boundary, kind in timeline:
        work.charge("comparisons")
        if kind == "introduced" and (boundary is None or v >= boundary):
            affected = True
        elif kind == "fixed" and v >= boundary:
            affected = False
        elif kind == "last_affected" and v > boundary:
            affected = False
    return affected
