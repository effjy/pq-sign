<div align="center">

<a href="https://github.com/effjy/pq-sign/"><img src="titles/pq-sign-title.svg" height="44" alt="PQ-SIGN"></a>

**Post-quantum detached file signing for Linux.**

[![License: MIT](https://img.shields.io/badge/License-MIT-teal?style=flat-square&labelColor=1a1a1a)](LICENSE)
[![Language: C](https://img.shields.io/badge/Language-C11-teal?style=flat-square&labelColor=1a1a1a)](#)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-8a2be2?style=flat-square&labelColor=1a1a1a)](#)
[![ML-DSA](https://img.shields.io/badge/FIPS_204-ML--DSA-teal?style=flat-square&labelColor=1a1a1a)](#)
[![SLH-DSA](https://img.shields.io/badge/FIPS_205-SLH--DSA-8a2be2?style=flat-square&labelColor=1a1a1a)](#)
[![KDF: Argon2id](https://img.shields.io/badge/KDF-Argon2id-teal?style=flat-square&labelColor=1a1a1a)](#)
[![AEAD: AES-256-GCM](https://img.shields.io/badge/AEAD-AES--256--GCM-teal?style=flat-square&labelColor=1a1a1a)](#)
[![liboqs](https://img.shields.io/badge/built_on-liboqs-8a2be2?style=flat-square&labelColor=1a1a1a)](https://github.com/open-quantum-safe/liboqs)

Sign and verify files with NIST's post-quantum signature standards —
**ML-DSA** (FIPS&nbsp;204, Dilithium) and **SLH-DSA** (FIPS&nbsp;205, SPHINCS+) —
with secret keys protected at rest by **Argon2id&nbsp;+&nbsp;AES-256-GCM**.

[Why](#-why) · [Demo](#-demo) · [Install](#-install) · [Usage](#-usage) · [Algorithms](#-algorithms) · [File formats](#-file-formats) · [Security](#-security-notes)

</div>

---

## 💡 Why

Most signing tools (GPG, `minisign`, `signify`) rely on RSA or Ed25519 —
classical schemes that a cryptographically relevant quantum computer would
break. `pq-sign` fills that gap with a small, dependency-light CLI built on the
lattice- and hash-based standards selected by NIST: locked-down at rest,
self-describing on the wire, no surprises.

- 🛡️ **Two NIST standards** — lattice-based **ML-DSA** (fast, compact) and
  hash-based **SLH-DSA** (conservative, larger signatures).
- 📎 **Detached signatures** — a self-describing `.sig` blob carries the scheme
  and a fingerprint of the signing key, so `verify` needs no extra flags. The
  secret key embeds its public key, so every signature is bound to its signer
  and `verify` rejects a wrong-key signature before running the math.
- 🔐 **Encrypted secret keys** — `--encrypt` wraps the private key with
  **Argon2id** (64&nbsp;MiB, t=3) and **AES-256-GCM**, with the algorithm and
  public key bound in as AEAD. The passphrase never touches disk.
- 🌊 **Streaming hash** — files are signed over a domain-separated SHA-256
  digest, so signing a 10&nbsp;GB image never loads it into memory.
- 🧹 **Defensive hygiene** — secret material is `mlock`ed against swap and wiped
  with `OPENSSL_cleanse`; key files are written `0600` and **crash-safely**
  (staged to a temp file, `fsync`ed, then atomically renamed).

---

## 🎬 Demo

```console
$ pq-sign keygen --out alice --alg ml-dsa-65
Generated ML-DSA-65 keypair
  public key:  alice.pub
  secret key:  alice.key
  fingerprint: 366167c723682901

$ pq-sign sign --key alice.key contract.txt
Signed 'contract.txt' with ML-DSA-65
  signature: contract.txt.sig (3309 bytes)

$ pq-sign verify --pub alice.pub contract.txt
VERIFY OK: 'contract.txt'
  algorithm:   ML-DSA-65
  signer:      366167c723682901

# …tamper with the file and the signature no longer holds:
$ echo "sneaky edit" >> contract.txt
$ pq-sign verify --pub alice.pub contract.txt
VERIFY FAILED: 'contract.txt' — signature is invalid
$ echo $?
2
```

> 💡 Add `--encrypt` to `keygen` to wrap the secret key behind a passphrase
> (Argon2id + AES-256-GCM); `sign` will then prompt for it.

---

## 📦 Install

`pq-sign` depends on three libraries:

| Dependency | Provides | Typical source |
|:---|:---|:---|
| **OpenSSL ≥ 3.0** | SHA-256, AES-256-GCM, CSPRNG | distro package |
| **libargon2** | Argon2id key derivation | distro package |
| **liboqs** | ML-DSA / SLH-DSA signatures | built from source (below) |

### 1. Install the system packages

OpenSSL and Argon2 are packaged everywhere; you also need a compiler,
`pkg-config`, and (to build liboqs) `git`, `cmake`, and `ninja`.

```sh
# Debian / Ubuntu
sudo apt install build-essential pkg-config git cmake ninja-build \
                 libssl-dev libargon2-dev

# Fedora
sudo dnf install gcc make pkgconf-pkg-config git cmake ninja-build \
                 openssl-devel libargon2-devel

# Arch
sudo pacman -S base-devel pkgconf git cmake ninja openssl argon2
```

### 2. Install liboqs globally (recommended)

[liboqs](https://github.com/open-quantum-safe/liboqs) is the library that
provides the post-quantum signature schemes. It is rarely packaged by
distributions, so you build it once from source and install it **system-wide**
into `/usr/local`. After this, a plain `make` and `./pq-sign` work with no
environment variables.

**The easy way** — the bundled script does everything below for you:

```sh
./setup-liboqs.sh        # builds a minimal liboqs and installs it to /usr/local
```

**Or do it by hand** — the exact same steps, if you prefer to see them:

```sh
# 1. Fetch the source
git clone --depth 1 --branch 0.12.0 \
    https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# 2. Configure a minimal, shared build installed to /usr/local
#    (drop -DOQS_MINIMAL_BUILD to build every algorithm liboqs ships)
cmake -GNinja -B build \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_sphincs_sha2_128f_simple;SIG_sphincs_sha2_192f_simple;SIG_sphincs_sha2_256f_simple"

# 3. Install system-wide and refresh the shared-library cache
sudo ninja -C build install
sudo ldconfig
cd ..
```

This installs:

```
/usr/local/lib/liboqs.so*               the shared library
/usr/local/include/oqs/*.h              the headers
/usr/local/lib/pkgconfig/liboqs.pc      the pkg-config file
```

> **Verify it worked:** `pkg-config --modversion liboqs` should print a version
> (e.g. `0.12.0`). If it says *"not found"*, see [Troubleshooting](#-troubleshooting).

### 3. Build and install pq-sign

With liboqs installed globally, this is all it takes:

```sh
make             # builds the ./pq-sign binary
make check       # (optional) run the end-to-end test suite
sudo make install   # (optional) install to /usr/local/bin
```

That's it — run `pq-sign list` to confirm.

---

## 🩺 Troubleshooting

**`Package 'liboqs' was not found in the pkg-config search path`**
liboqs isn't installed, or its `.pc` file isn't where pkg-config looks.

- Confirm `/usr/local/lib/pkgconfig/liboqs.pc` exists. If it does but
  pkg-config still can't see it, your `pkg-config` may not search
  `/usr/local`. Tell it to:
  ```sh
  export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
  make
  ```
- If you installed liboqs as root and the directories came out unreadable
  (a strict `umask`), make them world-readable:
  ```sh
  sudo chmod -R a+rX /usr/local/include/oqs /usr/local/lib/pkgconfig
  ```
  (The `setup-liboqs.sh` script does this automatically.)

**`error while loading shared libraries: liboqs.so.X`** at run time
The dynamic linker can't find the library. After a system-wide install run
`sudo ldconfig`. If you installed liboqs to a non-standard prefix, point the
linker at it: `export LD_LIBRARY_PATH=/your/prefix/lib`.

**Installing without root.** If you can't use `sudo`, install liboqs into a
local prefix and tell the build where it is:

```sh
PREFIX="$PWD/.local" ./setup-liboqs.sh
make PKG_CONFIG_PATH="$PWD/.local/lib/pkgconfig"
LD_LIBRARY_PATH="$PWD/.local/lib" ./pq-sign list
```

---

## 🚀 Usage

```
pq-sign keygen --out <name> [--alg <alg>] [--encrypt]
pq-sign sign   --key <name.key> <file> [--out <file.sig>]
pq-sign verify --pub <name.pub> <file> [--sig <file.sig>]
pq-sign list
```

### Generate a keypair

```sh
$ pq-sign keygen --out alice --alg ml-dsa-65 --encrypt
Passphrase for secret key:
Confirm passphrase:
Generated ML-DSA-65 keypair
  public key:  alice.pub
  secret key:  alice.key  (encrypted)
  fingerprint: 4ff2cb0d5d60247f
```

Writes `alice.pub` (share freely) and `alice.key` (keep secret, mode `0600`).

### Sign

```sh
$ pq-sign sign --key alice.key report.pdf
Signed 'report.pdf' with ML-DSA-65
  signature: report.pdf.sig (3309 bytes)
```

### Verify

```sh
$ pq-sign verify --pub alice.pub report.pdf
VERIFY OK: 'report.pdf'
  algorithm:   ML-DSA-65
  signer:      4ff2cb0d5d60247f
```

`verify` exits `0` on success, `2` on an invalid or mismatched signature, and
`1` on usage/IO errors — convenient for scripts and CI gates.

---

## 🔢 Algorithms

Run `pq-sign list` to see which schemes your liboqs build enabled:

```
alias          canonical                    notes
-----          ---------                    -----
ml-dsa-44      ML-DSA-44                    lattice, NIST level 2
ml-dsa-65      ML-DSA-65                    lattice, NIST level 3  (default)
ml-dsa-87      ML-DSA-87                    lattice, NIST level 5
slh-dsa-128f   SPHINCS+-SHA2-128f-simple    hash-based, level 1
slh-dsa-192f   SPHINCS+-SHA2-192f-simple    hash-based, level 3
slh-dsa-256f   SPHINCS+-SHA2-256f-simple    hash-based, level 5
```

ML-DSA gives small, fast signatures; SLH-DSA trades size and speed for a
security argument that rests only on the hash function.

---

## 🗂️ Project layout

Everything needed to build and run lives in the repository:

```
pq-sign/
├── README.md           this file
├── LICENSE             MIT
├── Makefile            pkg-config driven build (liboqs · openssl · libargon2)
├── setup-liboqs.sh     fetches + builds a minimal liboqs into ./.local
├── include/
│   ├── pqsign.h            shared declarations
│   └── keyfile_internal.h  pure parse/decrypt seams (fuzzed & unit-tested)
├── src/
│   ├── main.c          CLI dispatch: keygen / sign / verify / list
│   ├── keyfile.c       armored key containers + Argon2id/AES-256-GCM at rest
│   ├── sigfile.c       self-describing binary signature container
│   └── util.c          secure memory, atomic writes, SHA-256, base64, prompts
├── tests/
│   ├── run.sh          end-to-end suite (keygen/sign/verify + tamper checks)
│   ├── kat/kat.c       known-answer + unit tests for the deterministic core
│   └── fuzz/           libFuzzer targets for the untrusted-input parsers
```

---

## 📄 File formats

**Keys** are armored text (PEM-like). An encrypted secret key:

```
-----BEGIN PQSIGN SECRET KEY-----
Alg: ML-DSA-65
Pub: <base64 public key>
Cipher: AES-256-GCM
KDF: Argon2id t=3 m=65536 p=1
Salt: dQ/OVSgJ8n9hYYjwaKOCLA==
Nonce: 0fuBMwWSr8FjBoY3
Tag: jxCgUllJdwJd2I6yDnqGcg==

<base64 ciphertext>
-----END PQSIGN SECRET KEY-----
```

The secret-key file embeds its matching public key in the `Pub:` header so
signing can always bind the signer fingerprint without a companion file. For
encrypted keys that public key (and the algorithm) are fed in as AEAD, so
neither can be swapped without failing the GCM tag.

**Signatures** are a compact binary container:

```
magic "PQSIGN" │ ver │ alg name │ SHA-256(pubkey) │ signature
```

Every v1.0 signature carries the signer fingerprint, and `verify` checks it
(constant-time) before running the verification — so a signature made for a
different key is rejected outright.

---

## 🧪 Testing

```sh
make check    # KAT/unit suite + keygen/sign/verify/tamper across schemes
make asan     # the same suite under AddressSanitizer + UBSan
make fuzz     # build libFuzzer targets (needs clang):
              #   ./fuzz_sigfile -max_total_time=60
              #   ./fuzz_keyarmor -max_total_time=60
```

- **`tests/kat/`** — known-answer vectors for the deterministic core: SHA-256,
  the strict base64 codec (incl. malformed-input rejection), the Argon2id KDF
  as parameterised here, the domain-separated signed-message construction, the
  signature container, and the key-armor parse/decrypt path with AEAD tamper
  detection.
- **`tests/fuzz/`** — the two parsers that consume attacker-controlled bytes
  (`sigfile_parse`, `key_armor_parse`) are split into pure, never-aborting
  functions and fuzzed under ASan/UBSan.
- **CI** builds, runs the suite under sanitizers, and runs a short fuzz smoke
  on every push.

Post-quantum signature correctness itself is delegated to liboqs (which ships
its own known-answer tests); these suites cover *pq-sign's* wiring around it.

---

## 🔒 Security notes

**What pq-sign defends.** A signature proves a file was vouched for by the
holder of a specific secret key, and detects any later modification. Verifying
needs only the public key; the secret key never leaves the machine.

- Files are signed over `SHA-256("pq-sign/v1" ‖ SHA-256(file))`. The context
  string is domain separation; bumping it invalidates old signatures. (File
  integrity is therefore bounded by SHA-256's collision resistance — a
  deliberate trade for streaming arbitrarily large files.)
- Every signature is **bound to its signer**: the secret key embeds its public
  key, so `verify` rejects a signature presented under the wrong key with a
  constant-time fingerprint check before running the verification.
- Secret keys at rest are encrypted with **Argon2id → AES-256-GCM**, with the
  algorithm and public key bound in as AEAD. The passphrase is read with
  terminal echo disabled, fed to Argon2id, and wiped immediately; a wrong
  passphrase is caught by the GCM tag, not by guesswork.
- In-memory secrets are `mlock`ed against swap and wiped with `OPENSSL_cleanse`;
  key files are written `0600` and crash-safely (temp + `fsync` + `rename`).

**Limits — read before trusting this with anything that matters.**

- 🧪 **It builds on liboqs, which is research-grade and not independently
  audited.** No amount of hardening in *this* code changes that. Treat the
  whole stack as not-yet-production until liboqs matures and an independent
  cryptographic audit of pq-sign has been done.
- The PQ standards themselves (FIPS 204/205, finalised 2024) are young and have
  seen far less cryptanalysis than RSA/ECDSA.
- `mlock` is best-effort: small stack values and the `getline` passphrase
  buffer are wiped but not locked, and a constrained `RLIMIT_MEMLOCK` downgrades
  the guarantee (pq-sign warns once when this happens).
- pq-sign does **not** establish *who* a key belongs to. Verifying a signature
  tells you the file was signed by a given key fingerprint — establishing that
  the fingerprint is really Alice's is out of scope (no web of trust, no PKI).

---

## 📜 License

MIT © 2026 Jean-Francois Lachance-Caumartin
