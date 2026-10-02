# SPDX-License-Identifier: Apache-2.0
# Synthetic inert fixtures and independent expected boundary tables.
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from advisory_offline_review import Limits, review_json
from advisory_offline_review.contracts import Rejected
from advisory_offline_review.input import read_regular_file

TIME = "2026-10-02T00:00:00Z"


def inventory(v="1.5", name="inert-demo", ecosystem="PyPI"):
    return {"schema_version": 1, "packages": [{"name": name, "version": v, "ecosystem": ecosystem}]}


def advisory(
    events=None, *, identity="SYNTHETIC-001", ranges=None, versions=None, name="inert-demo"
):
    affected = {"package": {"ecosystem": "PyPI", "name": name}}
    if ranges is None and events is not None:
        ranges = [{"type": "ECOSYSTEM", "events": events}]
    if ranges is not None:
        affected["ranges"] = ranges
    if versions is not None:
        affected["versions"] = versions
    return {"id": identity, "modified": "2026-10-01T00:00:00Z", "affected": [affected]}


def snapshot(*records, time=TIME):
    return {"schema_version": 1, "snapshot_time": time, "vulns": list(records)}


def encode(obj):
    return json.dumps(obj, ensure_ascii=True).encode()


def run(inv, snap, **kwargs):
    return review_json(encode(inv), encode(snap), as_of=TIME, **kwargs)


class Matching(unittest.TestCase):
    def test_interval_grid_against_independent_ordered_index_oracle(self):
        ordered = [
            "1.dev1",
            "1a1.dev1",
            "1a1",
            "1b1",
            "1rc1",
            "1",
            "1+abc",
            "1.post1.dev1",
            "1.post1",
            "1.1",
            "1!0",
        ]
        cases = 0
        # Expected inclusion comes from finite independently declared ordinal
        # positions, with no call to packaging or the runtime range algorithm.
        for lower in range(len(ordered)):
            for upper in range(lower + 1, len(ordered)):
                record = advisory([{"fixed": ordered[upper]}, {"introduced": ordered[lower]}])
                for index, v in enumerate(ordered):
                    expected = "FAIL" if lower <= index < upper else "PASS"
                    self.assertEqual(run(inventory(v), snapshot(record))["status"], expected)
                    cases += 1
        self.assertEqual(cases, 605)

    def test_fixed_boundary_table_and_unsorted_events(self):
        record = advisory([{"fixed": "2.0"}, {"introduced": "1.0"}])
        for v, expected in [
            ("0.9", "PASS"),
            ("1.0", "FAIL"),
            ("1.0.0", "FAIL"),
            ("1.9rc1", "FAIL"),
            ("2.0.dev1", "FAIL"),
            ("2.0", "PASS"),
            ("2.0.post1", "PASS"),
        ]:
            with self.subTest(v=v):
                r = run(inventory(v), snapshot(record))
                self.assertEqual(r["status"], expected)
                self.assertTrue(r["complete"])

    def test_introduced_zero_is_before_every_version(self):
        for v in ("0.dev0", "0a0", "0", "999!123"):
            self.assertEqual(
                run(inventory(v), snapshot(advisory([{"introduced": "0"}])))["status"], "FAIL"
            )
        record = advisory([{"introduced": "0"}, {"fixed": "0"}])
        self.assertEqual(run(inventory("0.dev1"), snapshot(record))["status"], "FAIL")
        self.assertEqual(run(inventory("0"), snapshot(record))["status"], "PASS")

    def test_last_affected_inclusive(self):
        record = advisory([{"introduced": "1"}, {"last_affected": "2.0"}])
        for v, expected in [
            ("1", "FAIL"),
            ("2.0rc1", "FAIL"),
            ("2.0", "FAIL"),
            ("2.0+local", "PASS"),
            ("2.0.post0", "PASS"),
        ]:
            self.assertEqual(run(inventory(v), snapshot(record))["status"], expected)

    def test_limits_apply_to_entire_range_and_multiple_are_or(self):
        record = advisory([{"limit": "2"}, {"introduced": "0"}, {"limit": "4"}, {"fixed": "3"}])
        for v, expected in [
            ("1", "FAIL"),
            ("2", "FAIL"),
            ("2.9", "FAIL"),
            ("3", "PASS"),
            ("4", "PASS"),
        ]:
            self.assertEqual(run(inventory(v), snapshot(record))["status"], expected)
        for limit in ("*", "1.*"):
            record = advisory([{"introduced": "0"}, {"limit": limit}])
            self.assertEqual(run(inventory("999"), snapshot(record))["status"], "FAIL")
        record = advisory([{"introduced": "0"}, {"limit": "2"}])
        self.assertEqual(run(inventory("2"), snapshot(record))["status"], "PASS")

    def test_reintroduction_disjoint_ranges_and_union_with_versions(self):
        ranges = [
            {
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "3"},
                    {"fixed": "4"},
                    {"introduced": "1"},
                    {"fixed": "2"},
                ],
            },
            {"type": "ECOSYSTEM", "events": [{"introduced": "6"}, {"last_affected": "7"}]},
        ]
        record = advisory(ranges=ranges, versions=["5.0"])
        for v, expected in [
            ("0", "PASS"),
            ("1", "FAIL"),
            ("2", "PASS"),
            ("3", "FAIL"),
            ("4", "PASS"),
            ("5", "FAIL"),
            ("6", "FAIL"),
            ("7", "FAIL"),
            ("7.1", "PASS"),
        ]:
            self.assertEqual(run(inventory(v), snapshot(record))["status"], expected)

    def test_pep440_order_epoch_prerelease_dev_post_local(self):
        # Independently specified PEP 440 order, not derived from the implementation.
        ordered = [
            "1.dev1",
            "1a1.dev1",
            "1a1",
            "1b1",
            "1rc1",
            "1",
            "1+abc",
            "1.post1.dev1",
            "1.post1",
            "1.1",
            "1!0",
        ]
        for start in range(len(ordered) - 1):
            record = advisory([{"introduced": ordered[start]}, {"fixed": ordered[start + 1]}])
            for index, v in enumerate(ordered):
                self.assertEqual(
                    run(inventory(v), snapshot(record))["status"],
                    "FAIL" if index == start else "PASS",
                )

    def test_pep440_normalization_and_package_name(self):
        for a, b in [
            ("v1.0", "1.0.0"),
            ("1.0a", "1.0a0"),
            ("1.0-1", "1.0.post1"),
            ("1.0dev", "1.0.dev0"),
            ("1.0+Ubuntu_1", "1.0+ubuntu.1"),
        ]:
            record = advisory(versions=[b], name="Inert_Demo")
            r = run(inventory(a, name="INERT..Demo"), snapshot(record))
            self.assertEqual(r["status"], "FAIL")
            self.assertEqual(r["packages"][0]["name"], "inert-demo")

    def test_wrong_name_no_match_and_wildcard_matches(self):
        r = run(inventory(), snapshot(advisory([{"introduced": "0"}], name="another")))
        self.assertEqual(r["packages"][0]["result"], "NO_KNOWN_MATCH")
        self.assertEqual(
            run(inventory(), snapshot(advisory([{"introduced": "0"}], name="*")))["status"], "FAIL"
        )

    def test_unsupported_ecosystems_range_domains_and_versions_open(self):
        for kind in ("SEMVER", "GIT", "unknown", None):
            record = advisory(
                ranges=[{"type": kind, "events": [{"introduced": "0"}, {"fixed": "deadbeef"}]}]
            )
            self.assertEqual(run(inventory(), snapshot(record))["status"], "OPEN")
        for v in (None, 1, "", "1.0.*", "==1.2", "main", "deadbeef"):
            self.assertEqual(run(inventory(v), snapshot())["status"], "OPEN")
        self.assertEqual(run(inventory(ecosystem="npm"), snapshot())["status"], "OPEN")
        record = advisory(versions=["1.5"])
        record["affected"][0]["package"]["ecosystem"] = "npm"
        self.assertEqual(run(inventory(), snapshot(record))["status"], "OPEN")

    def test_malformed_and_ambiguous_ranges_open(self):
        tables = [
            [],
            [{"fixed": "2"}],
            [{"introduced": "3"}, {"fixed": "2"}],
            [{"introduced": "1", "fixed": "2"}],
            [{"introduced": "0"}, {"unexpected": "2"}],
            [{"introduced": "0"}, {"fixed": "1"}, {"last_affected": "2"}],
            [{"introduced": "1"}, {"fixed": "1.0"}],
            [{"introduced": "not-a-version"}],
        ]
        for events in tables:
            self.assertEqual(run(inventory(), snapshot(advisory(events)))["status"], "OPEN")
        record = advisory(ranges=[{"type": "ECOSYSTEM", "events": "unknown"}])
        self.assertEqual(run(inventory(), snapshot(record))["status"], "OPEN")

    def test_match_and_open_coexist(self):
        record = advisory(
            versions=["1.5"], ranges=[{"type": "GIT", "events": [{"introduced": "0"}]}]
        )
        r = run(inventory(), snapshot(record))
        self.assertEqual(r["status"], "FAIL")
        self.assertFalse(r["complete"])
        self.assertTrue(r["issues"])

    def test_missing_affected_identity_and_version_scope_open(self):
        for obj in [
            {},
            {"affected": []},
            {"affected": [{}]},
            {"affected": [{"package": {"name": "inert-demo", "ecosystem": "PyPI"}}]},
        ]:
            record = {"id": "SYNTHETIC-1", "modified": TIME, **obj}
            self.assertEqual(run(inventory(), snapshot(record))["status"], "OPEN")


class SnapshotPolicy(unittest.TestCase):
    def test_empty_snapshot_is_only_no_known_match(self):
        r = run(inventory(), snapshot())
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(r["packages"][0]["result"], "NO_KNOWN_MATCH")
        for key in (
            "snapshot_authenticity",
            "inventory_completeness",
            "current_vulnerability_status",
            "cvp_eligibility",
        ):
            self.assertEqual(r[key], "OPEN")

    def test_stale_future_and_age_boundary(self):
        for date, expected in [
            ("2026-09-02T00:00:00Z", "PASS"),
            ("2026-09-01T23:59:59Z", "OPEN"),
            ("2026-10-02T00:00:01Z", "OPEN"),
        ]:
            self.assertEqual(run(inventory(), snapshot(time=date))["status"], expected)
        r = run(inventory(), snapshot(advisory([{"introduced": "0"}]), time="2026-08-01T00:00:00Z"))
        self.assertEqual(r["status"], "FAIL")
        self.assertFalse(r["complete"])

    def test_timestamps_and_schema_are_explicit(self):
        for text in (
            None,
            "2026-10-02",
            "2026-10-02T00:00:00+00:00",
            "2026-02-30T00:00:00Z",
            "2026-10-02T00:00:60Z",
            "2026-10-02T00:00:00.1234567Z",
        ):
            self.assertEqual(
                review_json(encode(inventory()), encode(snapshot()), as_of=text)["status"], "OPEN"
            )
        for text, expected in [
            ("1.0.0", "FAIL"),
            ("1.9.1", "FAIL"),
            ("1.10.0", "OPEN"),
            ("2.0.0", "OPEN"),
            ("1.09.0", "OPEN"),
            (1, "OPEN"),
        ]:
            record = advisory([{"introduced": "0"}])
            record["schema_version"] = text
            self.assertEqual(run(inventory(), snapshot(record))["status"], expected)

    def test_withdrawn_is_inactive_and_bad_withdrawal_cannot_hide(self):
        record = advisory([{"introduced": "0"}])
        record["withdrawn"] = "2026-10-01T00:00:00Z"
        self.assertEqual(run(inventory(), snapshot(record))["status"], "PASS")
        record["withdrawn"] = "2027-01-01T00:00:00Z"
        r = run(inventory(), snapshot(record))
        self.assertEqual(r["status"], "FAIL")
        self.assertFalse(r["complete"])
        record["withdrawn"] = "unknown"
        self.assertEqual(run(inventory(), snapshot(record))["status"], "OPEN")

    def test_latest_modified_duplicate_id_authoritative(self):
        old = advisory([{"introduced": "0"}])
        old["modified"] = "2026-09-30T00:00:00Z"
        new = advisory(versions=["3"])
        for records in [(new, old), (old, new)]:
            self.assertEqual(run(inventory(), snapshot(*records))["status"], "PASS")
        new["withdrawn"] = new["modified"]
        self.assertEqual(run(inventory(), snapshot(old, new))["status"], "PASS")

    def test_conflicting_equal_modified_id_retains_match_open(self):
        a = advisory(versions=["1.5"])
        b = advisory(versions=["3"])
        for records in [(a, b), (b, a)]:
            r = run(inventory(), snapshot(*records))
            self.assertEqual(r["status"], "FAIL")
            self.assertFalse(r["complete"])

    def test_alias_bridge_is_symmetric_transitive_and_order_independent(self):
        a = advisory(versions=["1.5"], identity="SYNTHETIC-A")
        a["aliases"] = ["CVE-2099-0001"]
        b = advisory(versions=["1.5"], identity="SYNTHETIC-B")
        b["aliases"] = ["SYNTHETIC-Y"]
        bridge = advisory(versions=["3"], identity="SYNTHETIC-C")
        bridge["aliases"] = ["CVE-2099-0001", "SYNTHETIC-Y"]
        for records in [(a, b, bridge), (bridge, b, a), (b, bridge, a)]:
            r = run(inventory(), snapshot(*records))
            self.assertEqual(r["known_match_count"], 1)
            self.assertEqual(
                set(r["packages"][0]["matches"][0]["ids"]),
                {"SYNTHETIC-A", "SYNTHETIC-B", "SYNTHETIC-C", "CVE-2099-0001", "SYNTHETIC-Y"},
            )

    def test_related_upstream_are_not_aliases_and_withdrawal_not_contagious(self):
        a = advisory(versions=["1.5"], identity="SYNTHETIC-A")
        a["related"] = ["SYNTHETIC-B"]
        a["upstream"] = ["SYNTHETIC-B"]
        b = advisory(versions=["1.5"], identity="SYNTHETIC-B")
        self.assertEqual(run(inventory(), snapshot(a, b))["known_match_count"], 2)
        b["withdrawn"] = b["modified"]
        b["aliases"] = [a["id"]]
        self.assertEqual(run(inventory(), snapshot(a, b))["status"], "FAIL")

    def test_metadata_unknown_and_duplicate_inventory_open(self):
        record = advisory(versions=["1.5"])
        record["aliases"] = [record["id"]]
        r = run(inventory(), snapshot(record))
        self.assertEqual(r["status"], "FAIL")
        self.assertFalse(r["complete"])
        inv = inventory()
        inv["packages"] *= 2
        self.assertEqual(run(inv, snapshot())["status"], "OPEN")
        self.assertEqual(run({"schema_version": 1, "packages": []}, snapshot())["status"], "OPEN")


class BoundsAndPrivacy(unittest.TestCase):
    def test_strict_json_duplicate_nonfinite_utf8_depth_surrogates(self):
        samples = [
            b'{"schema_version":1,"schema_version":1,"packages":[]}',
            b"NaN",
            b"Infinity",
            b'{"x":1e9999}',
            b'"\\ud800"',
            b"\xff",
            b"[" * 33 + b"0" + b"]" * 33,
            b'{"x":123456789012345678901}',
            b"{",
        ]
        for data in samples:
            r = review_json(data, encode(snapshot()), as_of=TIME)
            self.assertEqual(r["status"], "OPEN")
        snap = snapshot()
        snap["vulns"] = [{"id": "SYNTHETIC-1", "modified": TIME, "aliases": ["X"]}]
        data = encode(snap).replace(b'"modified":', b'"id":"SYNTHETIC-2", "modified":')
        self.assertEqual(review_json(encode(inventory()), data, as_of=TIME)["status"], "OPEN")

    def test_budgets_and_unknowns_cannot_pass(self):
        inv, snap = inventory(), snapshot(advisory([{"introduced": "0"}]))
        for limits in (
            Limits(inventory_bytes=5),
            Limits(snapshot_bytes=5),
            Limits(depth=2),
            Limits(nodes=5),
        ):
            self.assertEqual(run(inv, snap, limits=limits)["status"], "OPEN")
        for limits, field in [(Limits(advisories=1), "vulns"), (Limits(packages=1), "packages")]:
            if field == "vulns":
                snap["vulns"] *= 2
            else:
                inv["packages"] *= 2
            self.assertEqual(run(inv, snap, limits=limits)["status"], "OPEN")
        record = advisory(versions=["1", "2"])
        self.assertEqual(
            run(inventory(), snapshot(record), limits=Limits(total_versions=1))["status"], "OPEN"
        )
        record["aliases"] = ["X", "Y"]
        self.assertEqual(
            run(inventory(), snapshot(record), limits=Limits(total_aliases=1))["status"], "OPEN"
        )

    def test_comparison_budget_preserves_known_match(self):
        record = advisory(versions=["1.5", "2", "3"])
        r = run(inventory(), snapshot(record), limits=Limits(comparisons=1))
        self.assertEqual(r["status"], "FAIL")
        self.assertFalse(r["complete"])
        self.assertEqual(r["known_match_count"], 1)
        self.assertEqual(r["work_used"]["comparisons"], 1)
        r = run(inventory("0"), snapshot(record), limits=Limits(comparisons=1))
        self.assertEqual(r["status"], "OPEN")

    def test_report_budget_preserves_known_match(self):
        inv = inventory()
        inv["packages"] = [
            {"name": "inert-demo", "version": str(v), "ecosystem": "PyPI"} for v in range(80)
        ]
        r = run(inv, snapshot(advisory([{"introduced": "0"}])), limits=Limits(report_bytes=4096))
        self.assertEqual(r["status"], "FAIL")
        self.assertFalse(r["complete"])
        self.assertEqual(r["known_match_count"], 80)
        self.assertLess(len(encode(r)), 4096)

    def test_api_contract_limits_and_dependency_version(self):
        for bad in (False, 0, {}, "limits"):
            with self.assertRaises(TypeError):
                run(inventory(), snapshot(), limits=bad)
        for bad in (False, -1, 366, "30"):
            self.assertEqual(run(inventory(), snapshot(), maximum_age_days=bad)["status"], "OPEN")
        with self.assertRaises(ValueError):
            Limits(packages=False)
        with self.assertRaises(ValueError):
            Limits(report_bytes=4095)
        with patch("packaging.__version__", "26.2"):
            self.assertEqual(run(inventory(), snapshot())["status"], "OPEN")

    def test_immutable_inputs_ignored_metadata_no_network_or_subprocess(self):
        record = advisory([{"introduced": "0"}])
        record.update(
            details="SENSITIVE_LOCAL_MARKER",
            references=[{"url": "https://user:SECRET@inert.invalid/"}],
        )
        inv, snap = inventory(), snapshot(record)
        before = deepcopy((inv, snap))
        a, b = encode(inv), encode(snap)
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network forbidden")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess forbidden")),
        ):
            r = review_json(a, b, as_of=TIME)
        self.assertEqual((inv, snap), before)
        self.assertEqual((a, b), (encode(inv), encode(snap)))
        self.assertEqual(r["status"], "FAIL")
        for secret in ("SENSITIVE_LOCAL_MARKER", "user:", "SECRET", "inert.invalid"):
            self.assertNotIn(secret, json.dumps(r))


class LocalAndCLI(unittest.TestCase):
    def test_regular_input_hash_preserved_and_budgets(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / "sample.json"
            p.write_bytes(encode(inventory()))
            before = hashlib.sha256(p.read_bytes()).hexdigest()
            self.assertEqual(read_regular_file(p, 524288), p.read_bytes())
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), before)
            with self.assertRaises(Rejected):
                read_regular_file(p, 5)
            for bad in (-1, 0, True, 4194305):
                with self.assertRaises(Rejected):
                    read_regular_file(p, bad)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor contract")
    def test_symlinks_parents_fifo_directory_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            real = base / "real"
            real.mkdir()
            f = real / "a"
            f.write_bytes(b"{}")
            (base / "link").symlink_to(real, target_is_directory=True)
            (base / "leaf").symlink_to(f)
            fifo = base / "fifo"
            os.mkfifo(fifo)
            for p in (base / "link/a", base / "leaf", base / "link/../real/a", fifo, real):
                with self.assertRaises((Rejected, OSError)):
                    read_regular_file(p, 100)

    def test_read_metadata_changes_short_reads_platform_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / "file"
            p.write_bytes(b"{}")
            with patch("advisory_offline_review.input.os.read", return_value=b""):
                with self.assertRaises(Rejected):
                    read_regular_file(p, 100)
            before = p.stat()
            changed = type(
                "Info",
                (),
                {
                    name: getattr(before, name)
                    for name in (
                        "st_dev",
                        "st_ino",
                        "st_size",
                        "st_mtime_ns",
                        "st_ctime_ns",
                        "st_mode",
                    )
                },
            )()
            changed.st_mtime_ns += 1
            with patch("advisory_offline_review.input.os.fstat", side_effect=[before, changed]):
                with self.assertRaises(Rejected):
                    read_regular_file(p, 100)
            with patch("advisory_offline_review.input.os.name", "nt"):
                with self.assertRaises(Rejected):
                    read_regular_file(p, 100)

    def test_cli_status_errors_privacy_and_input_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            inv = base / "PRIVATE_INVENTORY.json"
            snap = base / "PRIVATE_SNAPSHOT.json"
            inv.write_bytes(encode(inventory()))
            before = inv.read_bytes()
            for record, expected in [
                (None, 0),
                (advisory([{"introduced": "0"}]), 1),
                (advisory(ranges=[{"type": "SEMVER", "events": [{"introduced": "0"}]}]), 2),
            ]:
                snap.write_bytes(encode(snapshot(*([] if record is None else [record]))))
                sb = snap.read_bytes()
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "advisory_offline_review",
                        str(inv),
                        str(snap),
                        "--as-of",
                        TIME,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(proc.returncode, expected, proc.stderr)
                self.assertEqual(proc.stderr, "")
                r = json.loads(proc.stdout)
                self.assertNotIn("PRIVATE_", proc.stdout)
                self.assertEqual(inv.read_bytes(), before)
                self.assertEqual(snap.read_bytes(), sb)
                self.assertEqual(r["snapshot_authenticity"], "OPEN")
            for args in (
                [],
                ["--unknown=PRIVATE_SECRET"],
                [str(inv), str(snap), "--as-of", TIME, "--maximum-age-days", "PRIVATE_SECRET"],
                ["PRIVATE_MISSING", str(snap), "--as-of", TIME],
            ):
                proc = subprocess.run(
                    [sys.executable, "-m", "advisory_offline_review", *args],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stderr, "")
                self.assertNotIn("PRIVATE_", proc.stdout)
                self.assertEqual(json.loads(proc.stdout)["status"], "OPEN")
            proc = subprocess.run(
                [sys.executable, "-m", "advisory_offline_review", "--help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("usage:", proc.stdout)


if __name__ == "__main__":
    unittest.main()
