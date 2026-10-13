# xorcrack

A tool for breaking **repeating-key XOR ciphers** on readable text.

Built for learning: the code is commented to explain each step.

```text
ciphertext[i] = plaintext[i] XOR key[i % len(key)]
```

## Usage

```bash
python xorcrack.py message.bin
python xorcrack.py message.bin --crib "HTB{"     # if you know part of the plaintext
python xorcrack.py message.bin --k 5 -v          # force key length
python xorcrack.py message.bin --lang en --out output.txt
```

No external dependencies required (Python 3.8+ only).

## How It Works

1. **Key length:** Index of coincidence (IC) and Hamming distance.

   When K is correct, the key cancels out when comparing blocks:

   `(p1 XOR k) XOR (p2 XOR k) = p1 XOR p2`

   This reveals the statistical properties of the underlying language.

2. **Each key byte:** The bytes in `d[i::K]` use the same key byte. All 256 possible values are tested and scored according to how closely they resemble readable text.

3. **Joint refinement:** The best candidates for each key byte are tested by scoring the entire plaintext (letters + bigrams/trigrams). This corrects nearly correct keys (e.g., `a0` instead of `a9`).

4. **Optional crib:** If you know a fragment of the plaintext, the key bytes can be recovered using `key = ciphertext XOR crib`.

5. **Length penalty (MDL):** Longer keys can fit noise more easily, so a penalty is applied to avoid selecting multiples of the actual key length.

## Limitations

| Case | Does it work? |
|---|---|
| Short repeating key, English/Spanish plaintext | Yes |
| Very short text (< ~100 bytes) | Partially; use `--crib` |
| Non-text original (.exe, .zip, image) | Only with `--crib` using a known file header (`MZ`, `PK`, etc.) |
| Key that changes byte by byte (counter, PRNG) | No |
| Key as long as the message (one-time pad) | No |
| XOR combined with other layers (Base64, rotations) | Remove the other layers first |

If all candidate key lengths have low, flat IC values (~0.004), the data is probably not encrypted with repeating-key XOR, and this script is not the right tool.

## Practice Resources

- [Cryptopals](https://cryptopals.com) — Set 1, Challenge 6.
- [CryptoHack](https://cryptohack.org)
- [picoCTF](https://picoctf.org)
