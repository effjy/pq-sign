#!/usr/bin/env bash
# End-to-end smoke tests for pq-sign.
# Exercises keygen/sign/verify across schemes, plus tamper detection.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/pq-sign"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

cd "$TMP"
head -c 100000 /dev/urandom > doc.bin

for alg in ml-dsa-44 ml-dsa-65 ml-dsa-87 slh-dsa-128f; do
    echo "[$alg]"
    if "$BIN" keygen --alg "$alg" --out k >/dev/null 2>&1; then
        ok "keygen"
    else
        bad "keygen"; continue
    fi

    "$BIN" sign --key k.key doc.bin >/dev/null 2>&1 \
        && ok "sign" || bad "sign"

    "$BIN" verify --pub k.pub doc.bin >/dev/null 2>&1 \
        && ok "verify (good)" || bad "verify (good)"

    # Tamper with the document -> must fail.
    cp doc.bin doc2.bin; printf 'x' >> doc2.bin
    cp doc.bin.sig doc2.bin.sig
    if "$BIN" verify --pub k.pub doc2.bin >/dev/null 2>&1; then
        bad "tamper detection (modified file)"
    else
        ok "tamper detection (modified file)"
    fi

    # Wrong key -> must fail.
    "$BIN" keygen --alg "$alg" --out other >/dev/null 2>&1
    if "$BIN" verify --pub other.pub doc.bin >/dev/null 2>&1; then
        bad "wrong-key rejection"
    else
        ok "wrong-key rejection"
    fi

    rm -f k.key k.pub other.key other.pub doc.bin.sig doc2.bin*
done

echo
echo "Results: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
