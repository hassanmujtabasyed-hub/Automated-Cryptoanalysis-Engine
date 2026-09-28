"""
Monoalphabetic Substitution Cipher Cryptanalysis
Uses Frequency Analysis + Hill Climbing (Heuristic Search).
"""

import random
import re
import string
from collections import Counter
from language_model import composite_score, bigram_score, trigram_score, chi_squared_score


# English letter frequency order (most to least frequent)
ENGLISH_FREQ_ORDER = 'etaoinshrdlcumwfgypbvkjxqz'


def apply_key(ciphertext, key_map):
    """
    Apply a substitution key mapping to decrypt ciphertext.
    key_map: dict of cipher_letter -> plain_letter
    """
    result = []
    for char in ciphertext:
        if char.lower() in key_map:
            decrypted = key_map[char.lower()]
            result.append(decrypted.upper() if char.isupper() else decrypted)
        else:
            result.append(char)
    return ''.join(result)


def frequency_analysis_key(ciphertext):
    """
    Build initial key guess by mapping cipher letter frequencies
    to English letter frequencies.
    """
    text = re.sub(r'[^a-zA-Z]', '', ciphertext).lower()
    freq = Counter(text)
    cipher_order = [letter for letter, _ in freq.most_common()]
    
    # Pad with missing letters
    all_letters = list('abcdefghijklmnopqrstuvwxyz')
    for l in all_letters:
        if l not in cipher_order:
            cipher_order.append(l)
    
    plain_order = list(ENGLISH_FREQ_ORDER)
    key_map = {c: p for c, p in zip(cipher_order, plain_order)}
    return key_map


def key_to_string(key_map):
    """Convert key_map dict to 26-char string."""
    return ''.join(key_map.get(c, c) for c in 'abcdefghijklmnopqrstuvwxyz')


def string_to_key(key_str):
    """Convert 26-char string to key_map dict."""
    return {c: key_str[i] for i, c in enumerate('abcdefghijklmnopqrstuvwxyz')}


def swap_two_letters(key_map):
    """Randomly swap two mappings in the key (neighbor in hill climbing)."""
    key_str = list(key_to_string(key_map))
    i, j = random.sample(range(26), 2)
    key_str[i], key_str[j] = key_str[j], key_str[i]
    return string_to_key(''.join(key_str))


def hill_climbing_attack(ciphertext, iterations=5000, restarts=3, verbose=True):
    """
    Hill Climbing algorithm for substitution cipher cryptanalysis.
    
    Algorithm:
    1. Start with frequency analysis key
    2. Generate neighbor by swapping two letters in the key
    3. Accept if neighbor scores better
    4. Repeat for N iterations
    5. Restart with random perturbation to escape local optima
    """
    best_key = None
    best_score = -float('inf')
    best_plaintext = ""

    def score_key(key_map):
        plaintext = apply_key(ciphertext, key_map)
        return bigram_score(plaintext) + trigram_score(plaintext)

    for restart in range(restarts):
        # Start with frequency analysis key, add noise for restarts
        current_key = frequency_analysis_key(ciphertext)
        
        if restart > 0:
            # Perturb the best key found so far
            for _ in range(restart * 3):
                current_key = swap_two_letters(best_key if best_key else current_key)
        
        current_score = score_key(current_key)
        
        if verbose:
            print(f"\n  [Restart {restart+1}/{restarts}] Initial score: {current_score:.4f}")
        
        for iteration in range(iterations):
            neighbor_key = swap_two_letters(current_key)
            neighbor_score = score_key(neighbor_key)
            
            if neighbor_score > current_score:
                current_key = neighbor_key
                current_score = neighbor_score
        
        if current_score > best_score:
            best_score = current_score
            best_key = current_key
            best_plaintext = apply_key(ciphertext, best_key)
            
            if verbose:
                print(f"  [Restart {restart+1}] New best score: {best_score:.4f}")
                print(f"  Preview: {best_plaintext[:60]}...")

    return best_key, best_plaintext, best_score


def simulated_annealing_attack(ciphertext, max_temp=10.0, cooling=0.995, iterations=8000):
    """
    Simulated Annealing for substitution cipher.
    Allows occasional worse moves to escape local optima.
    """
    import math

    def score_key(key_map):
        plaintext = apply_key(ciphertext, key_map)
        return bigram_score(plaintext) + trigram_score(plaintext)

    current_key = frequency_analysis_key(ciphertext)
    current_score = score_key(current_key)
    best_key = current_key.copy()
    best_score = current_score

    temperature = max_temp

    for i in range(iterations):
        neighbor_key = swap_two_letters(current_key)
        neighbor_score = score_key(neighbor_key)
        delta = neighbor_score - current_score

        if delta > 0 or random.random() < math.exp(delta / max(temperature, 1e-10)):
            current_key = neighbor_key
            current_score = neighbor_score

        if current_score > best_score:
            best_score = current_score
            best_key = current_key.copy()

        temperature *= cooling

    best_plaintext = apply_key(ciphertext, best_key)
    return best_key, best_plaintext, best_score


def crack_substitution(ciphertext, method='hill_climbing', verbose=True):
    """
    Main function to crack monoalphabetic substitution cipher.
    Methods: 'hill_climbing' or 'simulated_annealing'
    """
    print("\n" + "="*60)
    print("MONOALPHABETIC SUBSTITUTION CRYPTANALYSIS")
    print("="*60)
    print(f"Method: {method.replace('_', ' ').title()}")
    print(f"Ciphertext: {ciphertext[:80]}{'...' if len(ciphertext)>80 else ''}")

    # Show frequency analysis
    text = re.sub(r'[^a-zA-Z]', '', ciphertext).lower()
    freq = Counter(text)
    print("\n[Frequency Analysis] Cipher letter frequencies (top 10):")
    for letter, count in freq.most_common(10):
        bar = '█' * int(count * 30 / max(freq.values()))
        print(f"  {letter.upper()}: {bar} ({count})")

    if method == 'simulated_annealing':
        best_key, best_plaintext, best_score = simulated_annealing_attack(ciphertext)
    else:
        best_key, best_plaintext, best_score = hill_climbing_attack(ciphertext, verbose=verbose)

    final_score = composite_score(best_plaintext)

    if verbose:
        print(f"\n[Result] Score: {final_score:.4f}")
        print(f"Key mapping (cipher → plain):")
        sorted_key = sorted(best_key.items())
        for i, (c, p) in enumerate(sorted_key):
            print(f"  {c.upper()}→{p.upper()}", end="  ")
            if (i + 1) % 6 == 0:
                print()
        print(f"\nDecrypted text:\n{best_plaintext}")

    return [(key_to_string(best_key), best_plaintext, final_score)]


def encrypt_substitution(plaintext, key_map):
    """
    Encrypt using substitution cipher.
    key_map: dict mapping plain_letter -> cipher_letter
    """
    result = []
    for char in plaintext:
        if char.lower() in key_map:
            enc = key_map[char.lower()]
            result.append(enc.upper() if char.isupper() else enc)
        else:
            result.append(char)
    return ''.join(result)


if __name__ == "__main__":
    # Test with a known substitution cipher
    sample_plaintext = (
        "The cryptanalysis of a monoalphabetic substitution cipher requires "
        "frequency analysis and heuristic search to recover the original message. "
        "English text has characteristic letter frequencies that help guide the search."
    )
    
    # Create a random key
    letters = list(string.ascii_lowercase)
    shuffled = letters.copy()
    random.shuffle(shuffled)
    test_key = {c: s for c, s in zip(letters, shuffled)}
    
    ct = encrypt_substitution(sample_plaintext, test_key)
    print(f"Original:  {sample_plaintext[:70]}...")
    print(f"Encrypted: {ct[:70]}...")
    
    crack_substitution(ct, method='hill_climbing', verbose=True)
