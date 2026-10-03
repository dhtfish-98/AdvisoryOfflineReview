# SPDX-License-Identifier: Apache-2.0
# New implementation by dhtfish98, 2026-10-02. See ORIGIN.md and LICENSE.
import argparse
import json

from .contracts import Limits, Rejected
from .input import read_regular_file
from .review import open_report, review_json


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Rejected("invalid_arguments")


def main(argv=None):
    parser = Parser(
        description="Offline PyPI/PEP440 OSV snapshot review; no API, installs or fixes"
    )
    parser.add_argument("inventory", help="Explicit local inventory JSON")
    parser.add_argument("snapshot", help="Explicit local authorized OSV snapshot envelope JSON")
    parser.add_argument("--as-of", required=True, help="Caller asserted UTC RFC3339 review time")
    parser.add_argument("--maximum-age-days", type=int, default=30)
    try:
        args = parser.parse_args(argv)
        limits = Limits()
        inventory = read_regular_file(args.inventory, limits.inventory_bytes)
        snapshot = read_regular_file(args.snapshot, limits.snapshot_bytes)
        report = review_json(
            inventory,
            snapshot,
            as_of=args.as_of,
            maximum_age_days=args.maximum_age_days,
            limits=limits,
        )
    except (ValueError, OSError, TypeError):
        report = open_report("input_or_arguments_rejected")
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
