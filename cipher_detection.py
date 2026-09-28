"""
Cipher Detection Module
Identifies cipher type using statistical analysis and pattern recognition.
"""

import re
import math
from collections import Counter


# English letter frequencies (percentage)
ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074
}

ENGLISH_IC = 0.0667  # Index of Coincidence for English


def clean_text(text):
    """Remove non-alphabetic characters and convert to lowercase."""
    return re.sub(r'[^a-zA-Z]', '', text).lower()


def index_of_coincidence(text):
    """
    Calculate the Index of Coincidence (IC) of a text.
    IC ≈ 0.0667 for English, ≈ 0.0385 for random text.
    """
    text = clean_text(text)
    n = len(text)
    if n < 2:
        return 0.0

    freq = Counter(text)
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return ic


def chi_squared_score(text):
    """
    Chi-squared test against English frequency distribution.
    Lower score = closer to English.
    """
    text = clean_text(text)
    n = len(text)
    if n == 0:
        return float('inf')

    freq = Counter(text)
    score = 0.0
    for letter in 'abcdefghijklmnopqrstuvwxyz':
        observed = freq.get(letter, 0)
        expected = ENGLISH_FREQ[letter] / 100.0 * n
        if expected > 0:
            score += ((observed - expected) ** 2) / expected
    return score


def has_word_boundaries(text):
    """Check if text has spaces suggesting word boundaries are preserved."""
    return ' ' in text


def repetition_patterns(text):
    """
    Kasiski-style: find repeated sequences in ciphertext.
    Useful for detecting Vigenère cipher.
    """
    text = clean_text(text)
    patterns = {}
    for length in range(3, 6):
        for i in range(len(text) - length):
            seq = text[i:i + length]
            positions = [j for j in range(len(text) - length + 1) if text[j:j + length] == seq]
            if len(positions) > 1:
                patterns[seq] = positions
    return patterns


def letter_frequency_deviation(text):
    """
    Measure how much the letter frequency deviates from English.
    Returns average absolute deviation.
    """
    text = clean_text(text)
    n = len(text)
    if n == 0:
        return float('inf')

    freq = Counter(text)
    total_dev = 0.0
    for letter in 'abcdefghijklmnopqrstuvwxyz':
        observed_pct = (freq.get(letter, 0) / n) * 100
        total_dev += abs(observed_pct - ENGLISH_FREQ[letter])
    return total_dev / 26


def detect_cipher(ciphertext):
    """
    Main cipher detection function.
    Returns dict: {cipher_type, confidence, notes}
    """
    text = clean_text(ciphertext)
    n = len(text)

    if n < 5:
        return {"cipher_type": "unknown", "confidence": 0, "notes": "Text too short"}

    ic = index_of_coincidence(text)
    freq_dev = letter_frequency_deviation(text)
    chi = chi_squared_score(text)
    patterns = repetition_patterns(text)

    notes = []
    notes.append(f"Index of Coincidence: {ic:.4f} (English≈0.0667, Random≈0.0385)")
    notes.append(f"Frequency Deviation: {freq_dev:.2f}%")
    notes.append(f"Chi-Squared Score: {chi:.2f}")
    notes.append(f"Repeated trigrams found: {len(patterns)}")

    # Decision logic
    if ic >= 0.060:
        # High IC → likely monoalphabetic or Caesar (single-alphabet substitution)
        if freq_dev < 10:
            return {
                "cipher_type": "caesar",
                "confidence": 0.85,
                "notes": notes,
                "ic": ic,
                "chi": chi
            }
        else:
            return {
                "cipher_type": "substitution",
                "confidence": 0.80,
                "notes": notes,
                "ic": ic,
                "chi": chi
            }
    elif 0.040 <= ic < 0.060:
        # Medium IC → likely Vigenère (polyalphabetic)
        return {
            "cipher_type": "vigenere",
            "confidence": 0.75,
            "notes": notes,
            "ic": ic,
            "chi": chi
        }
    else:
        # Very low IC → random / unknown
        return {
            "cipher_type": "unknown",
            "confidence": 0.50,
            "notes": notes,
            "ic": ic,
            "chi": chi
        }
