# Fixed origin and new implementation

Reference: [pypa/pip-audit at 828e77a4d4aa6bee8d315681db6928771d951a7c](https://github.com/pypa/pip-audit/tree/828e77a4d4aa6bee8d315681db6928771d951a7c). This is a design reference only; no pip-audit runtime or fixture is distributed. The new project independently chooses Apache-2.0. There is no upstream NOTICE in the fixed tree.

SOURCE_REVIEW.json binds 13 fully read selected files (2488 lines) to local SHA-256 and fixed Git blob identities: the four research-selected audit/requirements/OSV/fix files, the complete CLI, service and dependency contracts, version utility, virtual-environment/subprocess/cache risk paths, metadata and license. No upstream implementation or tests were executed. Other collectors, formatters, unrelated tests, third-party dependency closure and the entire upstream repository are not claimed semantically audited.

The new implementation uses independent strict JSON input contracts, explicit inventories, local OSV range matching, true PEP 440 comparisons, complete finite alias components and dated evidence states. It does not wrap or import pip-audit. Online PyPI/OSV/ESMS services, automatic inventory/environment resolution, pip/keyring subprocesses, cache writes/deletion, report-file writes, automatic fixes and SBOM formats are removed. In the fixed upstream, the virtual environment upgrades setup tools and invokes pip dry-run/report for target resolution; even that resolution work is absent from the new runtime.

This is the selected offline defensive workflow rewrite, not a full pip-audit feature replacement. New runtime, tests, CLI, docs and packaging were produced under repository-owner direction on 2026-10-02. Upstream authorship stays with upstream; neither an applicant's independent human contribution nor CVP identity/organization eligibility or approval is established here.

New implementation author: dhtfish98. This attribution applies to the new project implementation; original sources, licenses and third-party notices retain their authors. Automated checks do not establish independent human review or CVP eligibility.

## Current distribution and reference boundary

Actual packaged material is the new implementation and synthetic fixtures. packaging is an external dependency; no dependency runtime is bundled. pip-audit is a design reference only. New implementation author and maintainer: dhtfish98. Source identities and bounded research facts above remain provenance, not an assertion that those authors wrote or endorsed the new runtime.
