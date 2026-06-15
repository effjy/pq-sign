# Changelog

All notable changes to pq-sign are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-06-15

First stable release. Focused on hardening the implementation and building out
a test/fuzz/CI safety net around the existing functionality.

> **On-disk formats changed and are not compatible with 0.1.0.** Regenerate
> keys with `pq-sign keygen`; 0.1.0 keys and signatures will not load.

### Security / correctness
- **Signer binding is now mandatory.** Secret-key files embed their matching
  public key (a `Pub:` armor header), so every signature carries a real signer
  fingerprint and `verify` always checks it (constant-time) before running the
  signature verification. Removes the 0.1.0 behaviour where a missing companion
  `.pub` produced an all-zero fingerprint and the binding check was silently
  skipped.
- **Encrypted keys bind their identity.** The algorithm string and the embedded
  public key are fed into AES-256-GCM as AEAD, so neither can be altered without
  failing the authentication tag.
- **Crash-safe key writes.** Key files are staged to a temp file, `fsync`ed, and
  atomically `rename`d into place — a crash can no longer leave a truncated
  secret key.
- **Secrets are `mlock`ed** against being paged to swap (best-effort; warns once
  if `RLIMIT_MEMLOCK` is too low) in addition to being wiped.
- **Strict base64 decoding** replaces the lenient `EVP_DecodeBlock` path:
  non-alphabet bytes and malformed padding are now rejected.

### Robustness
- The untrusted-input parsers (`sigfile_parse`, `key_armor_parse`) are pure,
  operate on raw non-NUL-terminated bytes, and return errors instead of
  aborting — making them safe to fuzz and harder to crash.

### Testing & tooling
- New known-answer / unit suite (`tests/kat/`): SHA-256, strict base64,
  Argon2id, the domain-separated signed message, the signature container, and
  the key-armor parse/decrypt path with AEAD tamper detection.
- New libFuzzer targets (`tests/fuzz/`) for both parsers.
- New Makefile targets: `make kat`, `make asan` (AddressSanitizer + UBSan),
  `make fuzz`. `make check` now runs the KAT suite plus the end-to-end tests.
- GitHub Actions CI builds, runs the suite under sanitizers, and runs a short
  fuzz smoke.
- Documented an honest threat model and the liboqs-maturity / audit caveats.

### Notes
- This release hardens *pq-sign's* own code. Production trust still depends on
  liboqs maturing and an independent cryptographic audit; see the Security
  section of the README.

## [0.1.0]

- Initial version: `keygen` / `sign` / `verify` / `list` for ML-DSA and
  SLH-DSA via liboqs, with optional Argon2id + AES-256-GCM secret-key
  encryption.
