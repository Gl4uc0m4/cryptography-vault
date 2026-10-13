# xorcrack

A command-line tool for analyzing and breaking **repeating-key XOR ciphers** using frequency analysis and optional known-plaintext fragments.

Built for learning and experimenting with classical cryptanalysis techniques.

```text
ciphertext[i] = plaintext[i] XOR key[i % len(key)]
```

## Features

- Estimates key length using the Index of Coincidence (IC) and Hamming distance.
- Ranks possible key bytes using English or Spanish letter frequencies.
- Refines key candidates by scoring the resulting plaintext.
- Supports known-plaintext fragments through `--crib`.
- Saves recovered plaintext to a file.
- Requires no external dependencies.

## Requirements

- Python 3.8 or later
- Python standard library only

## Usage

Run the script from your terminal:

```bash
python xorcrack.py message.bin
```

### Common options

```bash
# Show additional analysis information
python xorcrack.py message.bin -v

# Force a specific key length
python xorcrack.py message.bin --k 5

# Search a wider range of key lengths
python xorcrack.py message.bin --maxk 80

# Select the plaintext language model
python xorcrack.py message.bin --lang en
python xorcrack.py message.bin --lang es

# Provide a known plaintext fragment
python xorcrack.py message.bin --crib "HTB{"

# Save the decrypted output
python xorcrack.py message.bin --out output.txt
```

Options can be combined:

```bash
python xorcrack.py message.bin --lang en --maxk 64 --out output.txt -v
```

## How It Works

### 1. Key Length Estimation

The tool uses the Index of Coincidence (IC) and Hamming distance to rank possible key lengths.

When two ciphertext bytes are encrypted with the same repeating-key XOR position, XORing them cancels out the key:

```text
(c1 XOR k) XOR (c2 XOR k) = p1 XOR p2
```

This helps reveal statistical patterns in the original plaintext.

### 2. Key Byte Analysis

For a candidate key length `K`, bytes at positions `i, i+K, i+2K, ...` share the same key byte.

The tool tests possible byte values and scores the resulting text using letter-frequency statistics.

### 3. Key Refinement

The strongest candidates for each key position are combined and evaluated against the complete plaintext. Letter frequencies and common character sequences help identify more plausible results.

### 4. Known-Plaintext Recovery

If part of the original plaintext is known, the `--crib` option can help recover the corresponding key bytes:

```text
key_byte = ciphertext_byte XOR plaintext_byte
```

This can be useful when the ciphertext is short or frequency analysis alone is inconclusive.

### 5. Key Length Penalty

Longer candidate keys can fit random patterns more easily. A penalty helps avoid selecting unnecessarily long keys, such as multiples of the actual key length.

## Limitations

| Scenario | Expected result |
|---|---|
| Repeating-key XOR with English or Spanish text | Usually suitable |
| Very short ciphertext (under ~100 bytes) | Less reliable; try `--crib` |
| Binary files such as `.exe`, `.zip`, or images | May require a known header or plaintext fragment |
| A key that changes for every byte | Not supported by this method |
| One-time pad with a key as long as the message | Cannot be solved by this approach alone |
| XOR combined with Base64 or other transformations | Remove the additional layers first |

If candidate key lengths produce consistently low and similar IC values (around `0.004`), the data may not be repeating-key XOR ciphertext.

Results depend on the plaintext language and length. Readable output alone does not guarantee that the recovered key is correct.

## Practice Resources

- [Cryptopals — Set 1, Challenge 6](https://cryptopals.com/sets/1/challenges/6)
- [CryptoHack](https://cryptohack.org)
- [picoCTF](https://picoctf.org)
