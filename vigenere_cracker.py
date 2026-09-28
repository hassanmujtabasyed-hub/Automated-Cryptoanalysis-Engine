"""
Vigenère Cipher Cryptanalysis Module
Uses Kasiski Examination + Index of Coincidence + Frequency Analysis.
"""

import re
import math
from collections import Counter
from language_model import composite_score, chi_squared_score

# English letter frequencies
ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074
}

ENGLISH_IC = 0.0667


def clean_text(text):
    return re.sub(r'[^a-zA-Z]', '', text).lower()


def vigenere_encrypt(plaintext, keyword):
    """Encrypt using Vigenère cipher."""
    keyword = keyword.lower()
    result = []
    k_len = len(keyword)
    k_idx = 0
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(keyword[k_idx % k_len]) - ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            k_idx += 1
        else:
            result.append(char)
    return ''.join(result)


def vigenere_decrypt(ciphertext, keyword):
    """Decrypt using Vigenère cipher."""
    keyword = keyword.lower()
    result = []
    k_len = len(keyword)
    k_idx = 0
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(keyword[k_idx % k_len]) - ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            k_idx += 1
        else:
            result.append(char)
    return ''.join(result)


def kasiski_examination(ciphertext, seq_length=3):
    """
    Kasiski Examination: Find repeated sequences and their spacing.
    The GCD of spacings hints at the key length.
    Returns a sorted list of candidate key lengths.
    """
    text = clean_text(ciphertext)
    sequences = {}

    for i in range(len(text) - seq_length):
        seq = text[i:i + seq_length]
        if seq not in sequences:
            sequences[seq] = []
        sequences[seq].append(i)

    # Only keep sequences appearing more than once
    spacings = []
    for seq, positions in sequences.items():
        if len(positions) > 1:
            for i in range(1, len(positions)):
                spacings.append(positions[i] - positions[i - 1])

    if not spacings:
        return []

    # Count GCD factors of all spacings
    factor_count = Counter()
    for spacing in spacings:
        for f in range(2, min(spacing + 1, 21)):
            if spacing % f == 0:
                factor_count[f] += 1

    # Return sorted by frequency
    return [k for k, v in factor_count.most_common(10)]


def index_of_coincidence(text):
    """Calculate IC of a text string."""
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def ic_key_length_test(ciphertext, max_key_len=20):
    """
    Test key lengths 2–max_key_len using IC of each column.
    Key length giving IC closest to English IC is best.
    Returns sorted list of (key_len, avg_ic, score).
    """
    text = clean_text(ciphertext)
    results = []

    for key_len in range(2, max_key_len + 1):
        # Split text into key_len columns (Caesar streams)
        columns = [''] * key_len
        for i, char in enumerate(text):
            columns[i % key_len] += char

        # Average IC across columns
        avg_ic = sum(index_of_coincidence(col) for col in columns if len(col) > 1) / key_len
        # Score: closeness to English IC
        score = -abs(avg_ic - ENGLISH_IC)
        results.append((key_len, avg_ic, score))

    results.sort(key=lambda x: x[2], reverse=True)
    return results


def find_caesar_shift(column_text):
    """
    For a single Vigenère column (treated as Caesar cipher),
    find the most likely shift using chi-squared test.
    """
    best_shift = 0
    best_chi = float('inf')

    n = len(column_text)
    if n == 0:
        return 0

    freq = Counter(column_text)

    for shift in range(26):
        chi = 0.0
        for i, letter in enumerate('abcdefghijklmnopqrstuvwxyz'):
            cipher_letter = chr((i + shift) % 26 + ord('a'))
            observed = freq.get(cipher_letter, 0)
            expected = ENGLISH_FREQ[letter] / 100.0 * n
            if expected > 0:
                chi += ((observed - expected) ** 2) / expected
        if chi < best_chi:
            best_chi = chi
            best_shift = shift

    return best_shift


def recover_key(ciphertext, key_length):
    """
    Given a key length, recover each key character using frequency analysis
    on each column independently.
    """
    text = clean_text(ciphertext)
    columns = [''] * key_length
    for i, char in enumerate(text):
        columns[i % key_length] += char

    key = ''
    for col in columns:
        shift = find_caesar_shift(col)
        key += chr(shift + ord('a'))

    return key


def crack_vigenere(ciphertext, top_n=5, max_key_len=15, verbose=True):
    """
    Main Vigenère cracking function.
    Steps:
    1. Kasiski Examination → candidate key lengths
    2. IC Test → refined key length candidates
    3. Frequency analysis per column → recover key
    4. Score and rank results
    """
    print("\n" + "="*60)
    print("VIGENÈRE CIPHER CRYPTANALYSIS")
    print("="*60)
    text = clean_text(ciphertext)
    print(f"Ciphertext length: {len(text)} chars")
    print(f"Overall IC: {index_of_coincidence(text):.4f} (English≈0.0667, Random≈0.0385)")

    # Step 1: Kasiski
    kasiski_lengths = kasiski_examination(ciphertext)
    if verbose and kasiski_lengths:
        print(f"\n[Kasiski] Candidate key lengths: {kasiski_lengths[:8]}")

    # Step 2: IC Test
    ic_results = ic_key_length_test(ciphertext, max_key_len=max_key_len)
    if verbose:
        print(f"\n[IC Test] Top key length candidates:")
        for kl, avg_ic, score in ic_results[:6]:
            print(f"  Length={kl:2d}  Avg IC={avg_ic:.4f}  Score={score:.4f}")

    # Combine candidates
    ic_top = [r[0] for r in ic_results[:6]]
    candidate_lengths = []
    seen = set()
    for l in kasiski_lengths[:4] + ic_top:
        if l not in seen and 2 <= l <= max_key_len:
            candidate_lengths.append(l)
            seen.add(l)
    if not candidate_lengths:
        candidate_lengths = [3, 4, 5, 6]

    # Step 3: Recover key for each candidate length
    candidates = []
    for key_len in candidate_lengths[:8]:
        recovered_key = recover_key(ciphertext, key_len)
        plaintext = vigenere_decrypt(ciphertext, recovered_key)
        score = composite_score(plaintext)
        candidates.append((recovered_key, plaintext, score))

    # Sort by score
    candidates.sort(key=lambda x: x[2], reverse=True)

    if verbose:
        print(f"\n[Results] Top {min(top_n, len(candidates))} decryptions:")
        print("-"*60)
        for i, (key, pt, score) in enumerate(candidates[:top_n], 1):
            print(f"  #{i} Key: '{key}' | Score: {score:.4f}")
            print(f"     {pt[:70]}{'...' if len(pt)>70 else ''}")
            print()

    return candidates[:top_n]


if __name__ == "__main__":
    # Test
    plaintext = (
        "Cryptography is the practice and study of techniques for secure communication "
        "in the presence of adversarial behavior. More generally, cryptography is about "
        "constructing and analyzing protocols that prevent third parties from reading "
        "private messages. Modern cryptography exists at the intersection of mathematics "
        "computer science and electrical engineering."
    )
    keyword = "crypto"
    ct = vigenere_encrypt(plaintext, keyword)
    print(f"Original:  {plaintext[:60]}...")
    print(f"Key:       {keyword}")
    print(f"Encrypted: {ct[:60]}...")
    
    results = crack_vigenere(ct)
    print(f"\nTop result key: '{results[0][0]}'")
    print(f"Correct key:    '{keyword}'")
