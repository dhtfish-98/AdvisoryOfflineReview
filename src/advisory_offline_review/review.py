# SPDX-License-Identifier: Apache-2.0
# New AI-assisted implementation, 2026-10-02. See ORIGIN.md and LICENSE.
"""Offline inventory-to-snapshot matching, without resolver or service calls."""

from dataclasses import asdict
from datetime import datetime, timedelta
import hashlib
import json
import re

import packaging

from .contracts import Limits, Rejected, Work, bounded_list
from .input import strict_json
from .ranges import contains, identifier, package_name, prepare_range, version


def digest(data):
    return hashlib.sha256(data).hexdigest()


def timestamp(value):
    # UTC RFC3339 subset, explicit seconds and up to microsecond precision.
    if type(value) is not str or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value
    ):
        raise Rejected("unsupported_or_invalid_timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise Rejected("unsupported_or_invalid_timestamp") from None


def open_report(code, limits=None):
    limits = Limits() if limits is None else limits
    return {
        "schema_version": 1,
        "status": "OPEN",
        "complete": False,
        "issues": [{"code": code}],
        "packages": [],
        "snapshot_authenticity": "OPEN",
        "inventory_completeness": "OPEN",
        "current_vulnerability_status": "OPEN",
        "cvp_eligibility": "OPEN",
        "limits": asdict(limits),
        "known_match_count": 0,
    }


def _issue(issues, code, **position):
    issues.append({"code": code, **position})


def _schema(obj):
    text = obj.get("schema_version", "1.0.0")
    if (
        type(text) is not str
        or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", text)
        or len(text) > 32
    ):
        raise Rejected("unsupported_osv_schema")
    triplet = tuple(int(x) for x in text.split("."))
    if not (1, 0, 0) <= triplet <= (1, 9, 1):
        raise Rejected("unsupported_osv_schema")


def _advisories(vulns, snapshot_time, as_of, limits, work, issues):
    latest = {}
    withdrawn_count = 0
    for index, obj in enumerate(vulns):
        pos = {"advisory_index": index}
        try:
            if type(obj) is not dict:
                raise Rejected("advisory_object_required")
            _schema(obj)
            identity = identifier(obj.get("id"))
            modified = timestamp(obj.get("modified"))
            if modified > snapshot_time or modified > as_of:
                _issue(issues, "advisory_modified_after_snapshot_or_review", **pos)
            if "published" in obj:
                published = timestamp(obj["published"])
                if published > modified:
                    _issue(issues, "published_after_modified", **pos)
            aliases = bounded_list(obj.get("aliases", []), limits.aliases, "aliases")
            work.charge("total_aliases", len(aliases))
            aliases = [identifier(x) for x in aliases]
            if len(set(aliases)) != len(aliases) or identity in aliases:
                _issue(issues, "duplicate_or_self_alias", **pos)
            withdrawn = None
            if "withdrawn" in obj:
                withdrawn = timestamp(obj["withdrawn"])
                if withdrawn > modified or withdrawn > snapshot_time or withdrawn > as_of:
                    _issue(issues, "withdrawn_after_modified_snapshot_or_review", **pos)
                    withdrawn = None  # Never let an invalid future withdrawal hide a match.
            item = {
                "id": identity,
                "aliases": set(aliases),
                "modified": modified,
                "withdrawn": withdrawn,
                "obj": obj,
                "index": index,
                "record_sha256": digest(
                    json.dumps(obj, sort_keys=True, ensure_ascii=True).encode()
                ),
            }
            previous = latest.get(identity)
            if previous is None or modified > previous["modified"]:
                latest[identity] = item
            elif (
                modified == previous["modified"]
                and item["record_sha256"] != previous["record_sha256"]
            ):
                _issue(issues, "conflicting_duplicate_advisory_id", **pos)
                # Both current claims are retained for matching rather than arbitrarily
                # selecting the nonmatching one; no-matches will still be OPEN.
                previous.setdefault("conflicts", []).append(item)
        except Rejected as error:
            _issue(issues, str(error), **pos)
    selected = []
    for item in latest.values():
        selected.append(item)
        selected.extend(item.get("conflicts", []))
    for item in selected:
        item["affected"] = []
        if item["withdrawn"] is not None:
            withdrawn_count += 1
            continue
        pos = {"advisory_index": item["index"]}
        try:
            affecteds = bounded_list(item["obj"].get("affected"), limits.affected, "affected")
            if not affecteds:
                raise Rejected("missing_affected_scope")
        except Rejected as error:
            _issue(issues, str(error), **pos)
            continue
        for ai, affected in enumerate(affecteds):
            location = dict(pos, affected_index=ai)
            try:
                if type(affected) is not dict or type(affected.get("package")) is not dict:
                    raise Rejected("missing_or_unknown_package_identity")
                pkg = affected["package"]
                if pkg.get("ecosystem") != "PyPI":
                    raise Rejected("unsupported_affected_ecosystem")
                name = "*" if pkg.get("name") == "*" else package_name(pkg.get("name"))
                prepared = {
                    "name": name,
                    "versions": [],
                    "ranges": [],
                    "advisory_index": item["index"],
                    "affected_index": ai,
                }
                item["affected"].append(prepared)
                versions = bounded_list(affected.get("versions", []), limits.versions, "versions")
                work.charge("total_versions", len(versions))
                for vi, text in enumerate(versions):
                    try:
                        prepared["versions"].append(version(text))
                    except Rejected as error:
                        _issue(issues, str(error), **location, version_index=vi)
                ranges = bounded_list(affected.get("ranges", []), limits.ranges, "ranges")
                for ri, obj in enumerate(ranges):
                    try:
                        prepared["ranges"].append(prepare_range(obj, limits))
                    except Rejected as error:
                        _issue(issues, str(error), **location, range_index=ri)
                if not versions and not ranges:
                    _issue(issues, "missing_version_scope", **location)
            except Rejected as error:
                _issue(issues, str(error), **location)
    return selected, withdrawn_count, len(latest)


def _components(records):
    # Iterative union/find implements symmetric and transitive alias equivalence,
    # including bridging records arriving after two separate components.
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != x:
            following = parent[x]
            parent[x] = root
            x = following
        return root

    for record in records:
        identity = record["id"]
        for alias in record["aliases"]:
            parent[find(alias)] = find(identity)
        find(identity)
    grouped = {}
    for identity in parent:
        grouped.setdefault(find(identity), []).append(identity)
    result = {}
    for identities in grouped.values():
        identities.sort(
            key=lambda x: (0 if x.startswith("PYSEC-") else 1 if x.startswith("CVE-") else 2, x)
        )
        for identity in identities:
            result[identity] = identities
    return result


def review_json(inventory_bytes, snapshot_bytes, *, as_of, maximum_age_days=30, limits=None):
    """Compare immutable caller bytes using an explicit UTC review-time assertion.

    A snapshot match is FAIL even when other inputs remain OPEN. PASS means
    NO_KNOWN_MATCH only in the finite supported snapshot, with fresh asserted
    timestamps; completeness/authenticity of real inventories/feeds stay OPEN.
    """
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise TypeError("limits must be Limits or None")
    if type(maximum_age_days) is not int or not 0 <= maximum_age_days <= 365:
        return open_report("invalid_maximum_age", limits)
    try:
        if packaging.__version__ != "26.3":
            raise Rejected("unsupported_packaging_version")
        review_time = timestamp(as_of)
        inventory = strict_json(inventory_bytes, limits.inventory_bytes, limits)
        snapshot = strict_json(snapshot_bytes, limits.snapshot_bytes, limits)
        if (
            type(inventory) is not dict
            or set(inventory) != {"schema_version", "packages"}
            or type(inventory["schema_version"]) is not int
            or inventory["schema_version"] != 1
        ):
            raise Rejected("inventory_schema_unsupported")
        if (
            type(snapshot) is not dict
            or set(snapshot) != {"schema_version", "snapshot_time", "vulns"}
            or type(snapshot["schema_version"]) is not int
            or snapshot["schema_version"] != 1
        ):
            raise Rejected("snapshot_schema_unsupported")
        packages = bounded_list(inventory["packages"], limits.packages, "inventory_packages")
        if not packages:
            raise Rejected("empty_inventory")
        vulns = bounded_list(snapshot["vulns"], limits.advisories, "advisories")
        snapshot_time = timestamp(snapshot["snapshot_time"])
    except Rejected as error:
        return open_report(str(error), limits)
    report = open_report("not_reviewed", limits)
    report.update(
        issues=[],
        input_inventory={"bytes": len(inventory_bytes), "sha256": digest(inventory_bytes)},
        input_snapshot={"bytes": len(snapshot_bytes), "sha256": digest(snapshot_bytes)},
        as_of=review_time.isoformat().replace("+00:00", "Z"),
        snapshot_time=snapshot_time.isoformat().replace("+00:00", "Z"),
        maximum_age_days=maximum_age_days,
    )
    issues = report["issues"]
    if snapshot_time > review_time:
        _issue(issues, "snapshot_in_future")
    elif review_time - snapshot_time > timedelta(days=maximum_age_days):
        _issue(issues, "stale_snapshot")
    work = Work(limits)
    records, withdrawn, unique = _advisories(
        vulns, snapshot_time, review_time, limits, work, issues
    )
    components = _components(records)
    seen = set()
    exhausted = False
    for pi, pkg in enumerate(packages):
        entry = {"inventory_index": pi, "status": "OPEN", "result": "UNKNOWN", "matches": []}
        report["packages"].append(entry)
        try:
            if type(pkg) is not dict or set(pkg) != {"ecosystem", "name", "version"}:
                raise Rejected("inventory_package_schema_unsupported")
            if pkg["ecosystem"] != "PyPI":
                raise Rejected("unsupported_inventory_ecosystem")
            name, v = package_name(pkg["name"]), version(pkg["version"])
            entry.update(name=name, version=str(v), ecosystem="PyPI")
            pair = name, v
            if pair in seen:
                _issue(issues, "duplicate_inventory_entry", inventory_index=pi)
            seen.add(pair)
            matches = {}
            for record in records:
                if exhausted:
                    break
                if record["withdrawn"] is not None:
                    continue
                matched = False
                try:
                    for affected in record["affected"]:
                        if affected["name"] not in (name, "*"):
                            continue
                        for listed in affected["versions"]:
                            work.charge("comparisons")
                            matched |= v == listed
                        for prepared in affected["ranges"]:
                            matched |= contains(v, prepared, work)
                except Rejected as error:
                    _issue(issues, str(error), inventory_index=pi)
                    exhausted = True
                # A later exhausted comparison budget cannot erase a match
                # already demonstrated by an earlier version/range clause.
                if matched:
                    ids = components[record["id"]]
                    group = matches.setdefault(ids[0], {"ids": ids, "record_indices": []})
                    group["record_indices"].append(record["index"])
            entry["matches"] = [matches[x] for x in sorted(matches)]
            if matches:
                entry.update(status="FAIL", result="SNAPSHOT_MATCH")
            else:
                entry["result"] = "NO_KNOWN_MATCH"
        except Rejected as error:
            _issue(issues, str(error), inventory_index=pi)
    report["complete"] = not issues
    for entry in report["packages"]:
        if not entry["matches"] and report["complete"]:
            entry["status"] = "PASS"
        elif not entry["matches"]:
            entry["result"] = "UNKNOWN"
    report["known_match_count"] = sum(len(p["matches"]) for p in report["packages"])
    report["status"] = (
        "FAIL" if report["known_match_count"] else "PASS" if report["complete"] else "OPEN"
    )
    report.update(
        work_used=work.used,
        advisory_counts={
            "supplied": len(vulns),
            "unique_ids": unique,
            "selected_records": len(records),
            "withdrawn_selected": withdrawn,
        },
        modified_dates=sorted({r["modified"].isoformat().replace("+00:00", "Z") for r in records}),
        withdrawal_dates=sorted(
            {
                r["withdrawn"].isoformat().replace("+00:00", "Z")
                for r in records
                if r["withdrawn"] is not None
            }
        ),
    )
    if len(json.dumps(report, ensure_ascii=True).encode()) > limits.report_bytes:
        compact = open_report("report_byte_budget", limits)
        compact.update(
            status="FAIL" if report["known_match_count"] else "OPEN",
            known_match_count=report["known_match_count"],
            input_inventory=report["input_inventory"],
            input_snapshot=report["input_snapshot"],
            omitted_package_count=len(report["packages"]),
            as_of=report["as_of"],
            snapshot_time=report["snapshot_time"],
        )
        return compact
    return report
