# Security policy

## Supported versions

Until v1.0 GA, only the most recent minor release receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |
| < 0.1   | no        |

## Reporting a vulnerability

**Do not file public GitHub issues for security vulnerabilities.**

Email `security@glassbox.example` (placeholder pending foundation
transfer) with a description, reproducer, and your preferred attribution.
We will acknowledge within 72 hours.

Per spec §23.7, our default disclosure window is 90 days from initial
report, with expedited disclosure for cryptographic issues. CVE
assignment goes through the project's CNA once one is established.

## Cryptographic issues

Any issue affecting canonical form, hashing, signing, the Merkle tree
construction, or the key registry is treated as cryptographic and
follows the expedited timeline. This includes refactors of code in
`glassbox-core` that change the bytes produced for an existing input;
such issues are reported and disclosed even if no exploitation is known.

## Release provenance

Every tagged release in CI:

1. Builds reproducibly under a pinned Rust toolchain (`rust-toolchain.toml`).
2. Generates a per-crate CycloneDX SBOM via `cargo cyclonedx`.
3. Signs each `glassbox` binary with **Sigstore keyless signing** (cosign +
   GitHub OIDC identity), producing `.sig` and `.crt` artifacts alongside
   the binary. Anyone can verify a release by running `cosign verify-blob`
   against the published certificate; identity is bound to the
   `release.yml` workflow on this repository.

See [.github/workflows/release.yml](.github/workflows/release.yml).

## What is in scope

- Forgery, modification, or silent deletion of ledger entries that
  bypass signature or hash-chain checks.
- Canonical-form differentials between implementations (a single input
  producing different bytes — and thus different hashes — in different
  builds).
- Cryptographic correctness issues in Ed25519 or ML-DSA-65 use,
  including misuse of nonces, seeds, or RNG sources.
- Storage backends that fail to fsync before acknowledging an append.
- Denial of service in the verifier (e.g., crafted records that cause
  unbounded memory consumption during walk).

## What is out of scope

- Self-DoS by the operator (e.g., filling the disk).
- Issues that require physical access to the HSM or signing key file
  on a configured deployment.
- Compromise of an external dependency that has already been patched
  upstream — please open an upstream advisory and a tracking issue here.
