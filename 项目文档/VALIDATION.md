> Historical validation for v0.1.2. Current release v0.1.3 is validated separately by its exact-commit CI and published artifacts.

# Current delivery validation — 0.1.2

New implementation author and maintainer: dhtfish98. This patch removes only source-reference or unbundled-dependency notice copies identified as unused. Licenses/notices associated with redistributed material and specific OPEN applicability questions are retained byte-for-byte. The new own runtime differs only in version metadata; parser and policy behavior are unchanged.

Current source inventory: `SOURCE_REVIEW_MANIFEST.json` (self-digest excluded). Current source, package-install and source-package rebuild checks are recorded in the separate 2026-10-03 license-cleanup delivery evidence. Package inventories, author/version metadata and runtime bytes are checked against this formal source. Installation uses frozen local dependencies; target inputs are never executed. New-commit hosted CI and publication remain pending until the owner publishes this patch.

Engineering results do not establish human contribution, identity, organization, safeguards impact or CVP admission.

## Historical previous delivery evidence

The remaining text describes earlier versions and their original material inventories. It does not describe or validate this patch.

# Current delivery validation — 0.1.1

New implementation author and maintainer: dhtfish98. Current source inventory: `SOURCE_REVIEW_MANIFEST.json` (this manifest excludes its own digest). The 2026-10-03 delivery preserves original upstream license and notice bytes; current runtime additionally validates the required OS capability flags and directory-relative support before local file reads.

The existing suite has 36 passing test cases in the current source and in a fresh consumer of this version. Package verification checks version/author, artifact RECORD or archive inventories, runtime bytes against the formal source, and retained third-party licenses. Consumer installation uses local frozen dependencies and does not run target inputs. Detailed current artifact hashes and execution receipts are kept in the separate delivery evidence.

New-commit hosted CI and publication remain pending until the repository owner publishes this version.

These engineering checks do not establish upstream authorship, independent human review, actual safeguards impact or CVP eligibility.

## Historical delivery evidence

The following sections describe the earlier delivery and retain its original versions and checks. They do not validate a later artifact.

# Validation evidence

Measured locally on 2026-10-02 with CPython 3.14.6 on macOS arm64, build 1.6.1,
setuptools 84.0.0, and pinned packaging 26.3. The engineering report
`research-cvp30-20261002/engineering/AdvisoryOfflineReview.json` binds final
source/artifact SHA-256 identities and the observed installed consumers.

32 unittest methods PASS from source, a fresh wheel consumer and a fresh sdist
consumer. An independent hand-declared PEP 440 ordered-index oracle checks 605
interval/version combinations; separate tables cover fixed/last_affected,
introduced-zero before 0.dev, multiple limit OR/infinity, reopened ranges,
epochs and normalized enumeration, prerelease/dev/post/local comparisons.

Tests also cover transitive alias bridges, related/upstream separation, active
alias alongside withdrawal, latest modified duplicate IDs, equal-date conflict
retaining a known match, stale/future dates, true version/name normalization,
unknown ecosystems/GIT/SEMVER and invalid version/schema inputs, duplicate JSON
keys at both levels, nonfinite numbers, UTF-8/surrogate/depth/node/byte budgets,
comparison and report limits retaining known FAIL, immutability, omission of
descriptive/URL secrets, and blocked network/subprocess during API matching.

Ordinary-file reads, symlink components/leaves, raw parent traversal, FIFO and
directory rejection, short reads, changed observed metadata and unsupported
platform are exercised. CLI tests use installed code for PASS/FAIL/OPEN exits
0/1/2, input-content preservation, fixed JSON errors without filename/argument
echo, and help. Extra direct installed entrypoint checks are recorded in the
engineering report. Distribution source/docs/attribution/license inclusion and
installed runtime identities are checked byte-for-byte.

All 13 fully read fixed pip-audit source/metadata/license files match local Git
blob metadata and independently fetched commit-pinned raw bytes. Upstream code
or tests were not executed. The official packaging wheel matches its published
SHA-256 and size. No whole dependency/upstream audit is claimed.

Synthetic fixtures and passing tests do not establish any real advisory,
current host vulnerability, authentic/complete feed or independent applicant
contribution. Python 3.11/3.14 GitHub CI is declared but remote execution is
OPEN. Live provider decisions and CVP approval remain OPEN.
