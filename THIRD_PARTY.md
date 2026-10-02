# Trusted runtime dependency

`packaging==26.3` supplies PEP 440 `Version` parsing/equality/order and validated PyPI `canonicalize_name`. These are mature version/name mechanisms; this reviewer does not substitute a regex for version comparison. The final runtime checks that the imported packaging version is the pinned version, otherwise OPEN.

Official [PyPI release metadata](https://pypi.org/pypi/packaging/26.3/json) was checked on 2026-10-02. The `packaging-26.3-py3-none-any.whl` has 129956 bytes and SHA-256 `d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c`. The downloaded wheel matched both. `requirements-runtime.lock` pins its version/hash; no packaging wheel or dependency runtime code is vendored in distributions.

Packaging is maintained by Donald Stufft and individual contributors, dual licensed Apache-2.0 OR BSD-2-Clause. Original LICENSE, LICENSE.APACHE and LICENSE.BSD are retained under third_party and installed license metadata. Relevant interfaces/source use were checked; a complete audit of packaging or its import closure is not claimed. The project's fixed pip-audit Apache license is separate from packaging's license alternatives.

Build verification used an isolated environment and trusted setup/test tools; their installation is engineering setup, not automatic installation of inventory entries at runtime. New runtime imports only the Python standard library and this pinned dependency.
