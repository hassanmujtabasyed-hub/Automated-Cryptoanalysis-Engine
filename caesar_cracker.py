"""
Caesar Cipher Cryptanalysis Module
Implements brute-force attack with frequency analysis scoring.
"""

from language_model import composite_score, chi_squared_score, rank_candidates


def caesar_decrypt(ciphertext, shift):
    """
    Decrypt ciphertext using Caesar cipher with given shift.
    Preserves spaces and non-alphabetic characters.
    """
    result = []
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            decrypted = chr((ord(char) - base - shift) % 26 + base)
            result.append(decrypted)
        else:
            result.append(char)
    return ''.join(result)


def caesar_encrypt(plaintext, shift):
    """Encrypt plaintext using Caesar cipher with given shift."""
    result = []
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted = chr((ord(char) - base + shift) % 26 + base)
            result.append(encrypted)
        else:
            result.append(char)
    return ''.join(result)


def brute_force_caesar(ciphertext, top_n=5):
    """
    Try all 26 possible Caesar shifts.
    Returns top N candidates sorted by language score.
    """
    candidates = []
    for shift in range(26):
        plaintext = caesar_decrypt(ciphertext, shift)
        candidates.append((f"shift={shift}", plaintext))

    ranked = rank_candidates(candidates)
    return ranked[:top_n]


def frequency_attack_caesar(ciphertext):
    """
    Use frequency analysis to find the most likely Caesar shift.
    Maps the most frequent ciphertext letter to 'e'.
    Returns best guess with explanation.
    """
    from collections import Counter
    import re

    text = re.sub(r'[^a-zA-Z]', '', ciphertext).lower()
    if not text:
        return None, "No alphabetic characters found"

    freq = Counter(text)
    most_common_letter = freq.most_common(1)[0][0]
    
    # 'e' is ASCII 101, find shift assuming most common = 'e'
    shift = (ord(most_common_letter) - ord('e')) % 26
    plaintext = caesar_decrypt(ciphertext, shift)
    
    analysis = {
        'method': 'Frequency Analysis',
        'most_common_cipher_letter': most_common_letter.upper(),
        'assumed_plaintext_letter': 'E',
        'derived_shift': shift,
        'plaintext': plaintext,
        'score': composite_score(plaintext)
    }
    return analysis


def crack_caesar(ciphertext, top_n=5, verbose=True):
    """
    Main function to crack a Caesar cipher.
    Combines brute force + frequency analysis.
    Returns list of results sorted by confidence.
    """
    print("\n" + "="*60)
    print("CAESAR CIPHER CRYPTANALYSIS")
    print("="*60)
    print(f"Ciphertext: {ciphertext[:80]}{'...' if len(ciphertext)>80 else ''}")
    
    # Brute force all shifts
    results = brute_force_caesar(ciphertext, top_n=top_n)
    
    # Frequency analysis
    freq_result = frequency_attack_caesar(ciphertext)
    
    if verbose:
        print(f"\n[Frequency Analysis] Most common letter: '{freq_result['most_common_cipher_letter']}'")
        print(f"  → Assumed plaintext 'E', derived shift = {freq_result['derived_shift']}")
        print(f"  → Score: {freq_result['score']:.4f}")
        print(f"\n[Brute Force] Top {top_n} candidates:")
        print("-"*60)
        for i, (key, plaintext, score) in enumerate(results, 1):
            print(f"  #{i} {key:12s} | Score: {score:.4f} | {plaintext[:50]}{'...' if len(plaintext)>50 else ''}")
    
    return results


if __name__ == "__main__":
    # Test
    original = "The quick brown fox jumps over the lazy dog"
    shift = 13
    ct = caesar_encrypt(original, shift)
    print(f"Original:   {original}")
    print(f"Encrypted (shift={shift}): {ct}")
    results = crack_caesar(ct, top_n=3)
