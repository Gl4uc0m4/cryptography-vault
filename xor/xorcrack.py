#!/usr/bin/env python3

"""
xorcrack - Recover repeating-key XOR keys from readable plaintext.

A command-line tool for analyzing and decrypting repeating-key XOR
ciphers using frequency analysis and optional known-plaintext hints.

Author: Gl4uc0m4
Version: 0.1.0
License: MIT

"""

import argparse
import math
from collections import Counter


FREQ = {
    "en": dict(zip(" etaoinshrdlucmwfgypbvkjxqz",
        [.18, .102, .075, .065, .062, .057, .057, .053, .050, .048, .034, .033,
         .023, .022, .020, .019, .018, .016, .016, .015, .012, .008, .006,
         .001, .001, .001, .001])),
    "es": dict(zip(" eaosrnidlctumpbhqygvfzjxkw",
        [.17, .12, .105, .085, .065, .063, .06, .05, .045, .035, .035, .03,
         .028, .025, .02, .012, .010, .009, .009, .008, .007, .005, .004,
         .003, .001, .001, .001])),
}

GRAMS = {
    "en": ["th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti",
           "es", "or", " th", "the", "he ", "ing", "and", "ion", "ent", " of",
           " to", " in", "tha", "ed ", "is ", " a "],
    "es": ["de", "en", "es", "la", "el", "os", "qu", "ue", "ra", "ar", "er",
           "co", " de", "que", "ue ", "ion", "ado", "los", " la", " el",
           " en", "ent", "es ", " y "],
}

PENALTY = 4.0

SIGNALS = (
    b" the ", b" and ", b" you ", b" is ", b" to ", b" of ",
    b" de ", b" que ", b"password", b"user", b"flag", b"htb{", b"http"
)


def build_lp(lang):
    """Build a log-probability table for all possible byte values."""
    lp = [math.log(1e-6)] * 256

    for c in range(32, 127):
        lp[c] = math.log(0.002)

    lp[10] = lp[13] = math.log(0.01)

    for ch, p in FREQ[lang].items():
        lp[ord(ch)] = math.log(p)
        lp[ord(ch.upper())] = math.log(p * 0.12)

    return lp


def make_scorers(lang):
    lp = build_lp(lang)
    grams = GRAMS[lang]

    def col_score(data):
        return sum(lp[c] for c in data)

    def text_score(data):
        score = sum(lp[c] for c in data)
        text = bytes(data).lower().decode("latin1")
        return score + 2.0 * sum(text.count(g) for g in grams)

    return col_score, text_score


def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def ic(data):
    """Calculate the index of coincidence."""
    n = len(data)
    if n < 2:
        return 0.0

    counts = Counter(data)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def key_lengths(data, maxk):
    rows = []

    for k in range(1, min(maxk, len(data) // 3) + 1):
        avg_ic = sum(ic(data[i::k]) for i in range(k)) / k

        blocks = [
            data[i:i + k]
            for i in range(0, len(data) - k + 1, k)
        ][:20]

        distances = [
            hamming(blocks[i], blocks[j]) / k
            for i in range(len(blocks))
            for j in range(i + 1, len(blocks))
        ]

        avg_hamming = (
            sum(distances) / len(distances) if distances else 8.0
        )

        rows.append((k, avg_ic, avg_hamming))

    if not rows:
        return [], []

    best_ic = max(row[1] for row in rows)
    candidates = [
        row[0] for row in rows if row[1] >= 0.6 * best_ic
    ]

    return rows, candidates


def decrypt(data, key):
    return bytes(
        b ^ key[i % len(key)]
        for i, b in enumerate(data)
    )


def column_rank(data, K, i, col_score, top=6):
    column = data[i::K]

    scores = [
        (col_score(bytes(b ^ g for b in column)), g)
        for g in range(256)
    ]

    scores.sort(reverse=True)
    return [g for _, g in scores[:top]]


def solve(data, K, col_score, text_score, forced=None,
          passes=4, verbose=False):
    """Find a key by scoring individual columns and the full plaintext."""
    forced = forced or {}

    candidates = [
        [forced[i]] if i in forced
        else column_rank(data, K, i, col_score)
        for i in range(K)
    ]

    key = [c[0] for c in candidates]
    sample = data[:20000]
    best = text_score(decrypt(sample, key))

    for _ in range(passes):
        changed = False

        for i in range(K):
            for g in candidates[i]:
                if g == key[i]:
                    continue

                trial = key[:]
                trial[i] = g
                score = text_score(decrypt(sample, trial))

                if score > best + 1e-9:
                    best = score
                    key = trial
                    changed = True

        if not changed:
            break

    if verbose:
        for i, value in enumerate(key):
            options = [f"{g:02x}" for g in candidates[i]]
            print(f"  byte {i}: {options} -> {value:02x}")

    return bytes(key), best


def crib_search(data, K, crib, col_score, text_score):
    """Try placing known plaintext at different offsets."""
    results = []
    sample = data[:4000]

    for offset in range(len(data) - len(crib) + 1):
        forced = {}
        valid = True

        for j, ch in enumerate(crib):
            pos = (offset + j) % K
            value = data[offset + j] ^ ch

            if pos in forced and forced[pos] != value:
                valid = False
                break

            forced[pos] = value

        if not valid:
            continue

        _, score = solve(
            sample, K, col_score, text_score,
            forced=forced, passes=2
        )

        results.append((score, offset, forced))

    results.sort(key=lambda item: item[0], reverse=True)
    return results[:3]


def best_for_K(data, K, col_score, text_score, crib, verbose=False):
    forced = {}

    if crib:
        results = crib_search(
            data, K, crib.encode(), col_score, text_score
        )

        if results:
            forced = results[0][2]

    return solve(
        data, K, col_score, text_score,
        forced=forced, verbose=verbose
    )


def main():
    parser = argparse.ArgumentParser(
        description="Break repeating-key XOR ciphers"
    )
    parser.add_argument("file")
    parser.add_argument("--k", type=int, help="force key length")
    parser.add_argument("--maxk", type=int, default=64)
    parser.add_argument("--lang", default="en", choices=FREQ)
    parser.add_argument("--crib", help="known plaintext fragment")
    parser.add_argument("--out", help="save decrypted data")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()

    if not data:
        parser.error("input file is empty")

    col_score, text_score = make_scorers(args.lang)

    counts = Counter(data)
    entropy = -sum(
        (v / len(data)) * math.log2(v / len(data))
        for v in counts.values()
    )

    print(f"[+] {len(data)} bytes, entropy {entropy:.2f}/8")

    if len(data) < 100:
        print("[!] Short input; results may be unreliable.")

    if args.k:
        if args.k < 1:
            parser.error("--k must be greater than zero")

        K = args.k
        key, _ = best_for_K(
            data, K, col_score, text_score,
            args.crib, args.verbose
        )
    else:
        rows, candidates = key_lengths(data, args.maxk)

        if not candidates:
            parser.error("not enough data to estimate the key length")

        print("[+] Most likely key lengths:")

        for k, avg_ic, avg_hamming in sorted(
            rows, key=lambda row: -row[1]
        )[:6]:
            print(
                f"    k={k:3d}  IC={avg_ic:.4f}  "
                f"Hamming={avg_hamming:.2f}"
            )

        print(f"[+] Candidates: {candidates[:8]}")

        results = {
            k: best_for_K(data, k, col_score, text_score, args.crib)
            for k in candidates[:8]
        }

        K = max(
            results,
            key=lambda k: results[k][1] - PENALTY * k
        )
        key = results[K][0]

        print(f"[+] Selected key length: {K}")

        if args.verbose:
            for k, (_, score) in results.items():
                print(f"    K={k:3d} score={score:.1f}")

            best_for_K(
                data, K, col_score, text_score,
                args.crib, verbose=True
            )

    plaintext = decrypt(data, key)
    words = sum(signal in plaintext.lower() for signal in SIGNALS)

    print(f"[+] Key: {key.hex(' ')} ({key!r})")
    print(f"[+] Recognizable words: {words}")
    print(plaintext.decode("latin1"))

    if args.out:
        with open(args.out, "wb") as f:
            f.write(plaintext)

        print(f"[+] Saved to {args.out}")


if __name__ == "__main__":
    main()
