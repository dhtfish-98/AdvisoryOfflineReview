# AdvisoryOfflineReview

Review an explicit local PyPI inventory against an authorized local OSV JSON snapshot. This is a new bounded offline matcher with pip-audit as a fixed source reference. It implements PEP 440 ordering through `packaging==26.3`; it never queries a vulnerability API, resolves dependencies, installs inventoried packages or applies fixes.

```sh
python -m pip install .
advisory-offline-review examples/inventory.json examples/snapshot.json --as-of 2026-10-02T00:00:00Z
```

Installing this reviewer and its pinned trusted library is setup work. Runtime does not install anything. The included advisory is explicitly synthetic and has no real vulnerability claim. Its example version matches, producing FAIL/exit 1.

The inventory envelope is exactly `{"schema_version":1,"packages":[{"ecosystem":"PyPI","name":"inert-demo","version":"1.5"}]}`. Every package must supply its exact declared version; requirements, ranges, URLs, lockfiles, import paths and automatic environment collection are unsupported. Names use validated PyPI normalization. Repeated canonical name/version entries remain present and OPEN. Multiple explicitly inventoried versions are evaluated separately.

The snapshot envelope is exactly `{"schema_version":1,"snapshot_time":"2026-10-02T00:00:00Z","vulns":[...]}`. Each member of `vulns` is an OSV record with `id`, `modified` and an active `affected` declaration. An empty `vulns` list is permitted; an empty inventory is OPEN. Arbitrary unwrapped API responses and compressed/archived files are unsupported. `snapshot_time` and required `--as-of` are caller assertions, never verified feed acquisition times. The maximum asserted age defaults to 30 days and can be set to 0..365 days. Stale/future dates remain OPEN.

PASS/exit 0 means **NO_KNOWN_MATCH** in this finite supported snapshot, with no known parsing, timestamp, scope or budget uncertainty. FAIL/exit 1 means a **SNAPSHOT_MATCH** under the declared package/version data. Known matches and OPEN conditions can coexist: status stays FAIL and `complete` is false. OPEN/exit 2 means malformed, unknown, unsupported or incomplete input. None proves actual package contents, environment completeness, current vulnerability status, source authenticity, mitigation or CVP eligibility; those fields remain OPEN on every result.

The version domain is PyPI/PEP 440, including epochs, pre/dev/post releases and local version numeric ordering. Enumeration uses normalized version equality. ECOSYSTEM events use inclusive `introduced`, exclusive `fixed`/`limit`, and inclusive `last_affected`; `introduced:"0"` starts before every version. Events may arrive unsorted, and a later introduction can reopen a range. Limits apply across the entire range; multiple limits are OR, and a limit containing `*` means infinity. All version/range declarations are a union. These semantics follow the [OSV evaluation specification](https://ossf.github.io/osv-schema/).

Unknown/non-PEP440 versions, SEMVER/GIT ranges and other ecosystems are OPEN. They are never passed through the PEP 440 comparator. Local identifiers describe potentially changed private builds: their numeric comparison is supported, while their actual code/vulnerability status remains OPEN. This tool does not assume that local labels prove a patch. It does not enumerate published versions or use installation specifier prerelease filtering.

OSV schema versions 1.0.0 through the checked 1.9.1 are accepted; absent schema_version means 1.0.0. Later schemas are OPEN. PyPI package `*` applies to the whole ecosystem. Equal-normalized contradictory/duplicate timeline boundaries, a closing event before the first introduction, mixed fixed/last_affected events, missing version scope or unsupported identifiers are conservative OPEN. RFC3339 dates must use UTC `Z`, explicit seconds and at most six fractional digits; alternate offsets, leap seconds and higher precision are OPEN. This is a documented semantic subset, not a complete OSV-schema validator.

For duplicate advisory IDs, the greatest modified date is authoritative. Identical records at the same date collapse. Different equal-date records remain OPEN and are both evaluated so an observed match is not discarded. Alias identity is symmetric/transitive, including late bridges between groups. A withdrawn latest record is inactive; withdrawing one alias record cannot cancel another active record. `related` and `upstream` do not merge identities. Summaries, details, severity, references, repository URLs and database/ecosystem-specific metadata do not change this package/version-only result and are not emitted or fetched. Invalid known date/alias/schema data remain OPEN. Withdrawn records' affected declarations are not evaluated.

```python
from advisory_offline_review import review_json

report = review_json(inventory_bytes, snapshot_bytes, as_of="2026-10-02T00:00:00Z")
```

Inputs are immutable bytes. Strict JSON rejects duplicate keys at any level, nonfinite numbers, invalid UTF-8, unpaired surrogates and excessive structure before matching. Reports include input hashes, normalized supported package names/versions, bounded advisory IDs, source indices and dates. Package names/versions and identifiers are intentionally visible evidence. Input filenames, raw invalid values, summary/details and URLs are omitted. Hashes are unsalted fingerprints, not secrecy guarantees.

Explicit local ordinary files are opened on POSIX through directory descriptors with `O_NOFOLLOW` for every component. Raw `..` components, symlinks, nonregular files, observed metadata changes and short/over-budget reads are OPEN. Missing required platform flags/facilities are OPEN. Reads may update filesystem atime; no intentional input write occurs. The reader cannot prove that an adversarial writer left no undetectable changes.

Limits can be lowered through `Limits`: 512 KiB inventory, 4 MiB snapshot, depth 32, 50,000 JSON nodes, 256 packages, 512 advisories, 64 affected entries/advisory, 64 ranges/affected entry, 256 events/range, 4096 versions/affected entry, 8192 enumerated versions total, 128 aliases/advisory, 4096 aliases total, 100,000 matching comparisons and 4 MiB JSON report. Values are positive exact integers within these ceilings; report minimum is 4096 bytes. Budget exhaustion is OPEN and does not erase known matches. Oversized reports produce a compact incomplete summary retaining the known-match count and FAIL when applicable. Finite parsing budgets are not an OS sandbox.

Python 3.11+. Every ordinary CLI invocation emits one JSON report to stdout, including usage/input errors, without argument/path echo; `--help` is the ordinary informational exception. See ORIGIN.md, SOURCE_REVIEW.json, THIRD_PARTY.md, DEFENSIVE_SCOPE.md and VALIDATION.md. New source/tests/docs are produced with Codex assistance under Apache-2.0, with original licenses/attribution retained. Repository presence does not establish independent applicant contribution or provider approval.
