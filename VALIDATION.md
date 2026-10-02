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
