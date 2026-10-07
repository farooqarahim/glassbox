# Contributing to Glassbox

Thank you for considering a contribution. Glassbox is a cryptographic
audit primitive, and that imposes some unusual discipline. Please read
this document before opening a non-trivial PR.

## Developer Certificate of Origin

All contributions are accepted under the Developer Certificate of
Origin 1.1 (https://developercertificate.org). Sign your commits with
`git commit -s`. We do not require a CLA — per the spec's open
governance commitments, no contributor must assign copyright to any
single corporate entity.

## Code of conduct

Be excellent to each other. We follow the Contributor Covenant 2.1; see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Before you open a PR

1. Run `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings`.
2. Run `cargo test --workspace`.
3. For any change that touches `glassbox-core`, add tests that cover
   the new behavior. Cryptographic and canonical-form changes additionally
   require a regression entry in the cross-version corpus (see
   `crates/glassbox-core/tests/corpus.rs`).

## Cryptographic discipline

The crate `glassbox-core` is treated as airframe-grade. Per spec §11.2:

- Any change to canonical form, hashing, signing, the Merkle tree, or
  the key registry requires **two reviewers** from different organizations.
- Any change to canonical-form output (even via dependency bump) requires
  an explicit annotation in `CHANGELOG.md` under a `Cryptographic` heading.
- Refactors that move bytes through the signing path count as cryptographic
  changes for review purposes.

## Scope discipline

Glassbox is intentionally small. Per the spec's `§7 Out of scope` and
`§9.5 Explicitly not shipping`:

- Glassbox is **not** an observability tool. It does not replace Datadog,
  Langfuse, or Helicone. PRs that add tracing, anomaly detection, or
  inference are out of scope.
- Glassbox does **not** make decisions. PRs that block or modify the
  application's request based on ledger state are out of scope.
- New storage backends, new SDKs, and new framework middleware are very
  welcome — they live in separate crates and never modify `glassbox-core`.

If you're not sure whether a feature fits, open an issue first.

## Commit message conventions

We follow Conventional Commits:

```
feat(core): add Merkle inclusion-proof builder
fix(storage): use BEGIN IMMEDIATE for append transaction
docs: explain post-quantum migration plan
```

Subject line ≤ 72 chars. Body wraps at 72. The body should explain *why*,
not just *what*.

## Reporting bugs

Use the issue tracker for non-security bugs. Include a minimal reproducer
and the output of `glassbox --version`. Security-relevant bugs go through
[SECURITY.md](SECURITY.md) instead.
