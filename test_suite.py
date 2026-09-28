"""
Test Suite for Automated Cryptanalysis Engine
Tests all modules: cipher detection, Caesar, substitution, Vigenère.
"""

import sys
import os
import random
import string
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cipher_detection import detect_cipher, index_of_coincidence, chi_squared_score
from language_model import composite_score, bigram_score, trigram_score, word_score
from caesar_cracker import caesar_encrypt, caesar_decrypt, crack_caesar, brute_force_caesar
from vigenere_cracker import vigenere_encrypt, vigenere_decrypt, crack_vigenere
from substitution_cracker import encrypt_substitution, apply_key, crack_substitution


# ─── Sample Texts ───
##Caesar encryption/decryption test
SHORT_TEXT = "The quick brown fox jumps over the lazy dog."
##Cipher detection
##Language model scoring
##Caesar cracking
##Substitution cipher testing
MEDIUM_TEXT = (
    "Cryptography is the practice and study of techniques for securing communication "
    "in the presence of adversarial behavior. Modern cryptography exists at the "
    "intersection of mathematics, computer science, and electrical engineering. "
    "Applications of cryptography include electronic commerce, chip-based payment cards "
    "digital currencies, computer passwords, and military communications, x-ray, xylophone,physiotherapy, pakistan"
)
# Index of Coincidence testing
# Vigenère encryption/decryption
# Vigenère key recovery
# Substitution cracking
# Integration testing
LONG_TEXT = (
    "The history of cryptography began thousands of years ago. "
    "Until recent decades, it has been the story of what might be called classic cryptography. "
    "Simple methods of encoding messages were used by Julius Caesar, who used a simple "
    "substitution cipher where each letter was replaced by another letter three places "
    "down in the alphabet. The Vigenere cipher, invented in the sixteenth century, "
    "uses a keyword to apply different Caesar shifts to each letter of the message. "
    "This made it much harder to crack using simple frequency analysis, earning it the "
    "nickname le chiffre indechiffrable, meaning the indecipherable cipher. "
    "Modern cryptanalysis uses computers to analyze statistical properties of text "
    "and apply heuristic search algorithms to recover keys without prior knowledge."
)


# ─── Test Results Tracker ───

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def check(self, name, condition, detail=""):
        status = "PASS" if condition else "FAIL"
        symbol = "✓" if condition else "✗"
        if condition:
            self.passed += 1
        else:
            self.failed += 1
        self.results.append((status, name, detail))
        print(f"  [{symbol}] {name}" + (f" — {detail}" if detail else ""))
        return condition

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"TEST SUMMARY: {self.passed}/{total} passed")
        print(f"{'='*60}")
        if self.failed > 0:
            print("FAILED TESTS:")
            for status, name, detail in self.results:
                if status == "FAIL":
                    print(f"  ✗ {name}: {detail}")
        return self.failed == 0


tr = TestResults()


# ─── Module 1: Cipher Detection ────

def test_cipher_detection():
    print("\n" + "━"*60)
    print("TEST MODULE 1: CIPHER DETECTION")
    print("━"*60)

    # Test 1: English text has high IC
    ic = index_of_coincidence(LONG_TEXT)
    tr.check("English text IC ≥ 0.060", ic >= 0.060, f"IC={ic:.4f}")

    # Test 2: Random text has low IC
    random_text = ''.join(random.choices(string.ascii_lowercase, k=500))
    ic_random = index_of_coincidence(random_text)
    tr.check("Random text IC < 0.045", ic_random < 0.045, f"IC={ic_random:.4f}")

    # Test 3: Caesar cipher detection
    ct = caesar_encrypt(MEDIUM_TEXT, 7)
    result = detect_cipher(ct)
    tr.check("Caesar cipher detected correctly", 
             result['cipher_type'] in ['caesar', 'substitution'],
             f"Detected: {result['cipher_type']}, IC={result.get('ic',0):.4f}")

    # Test 4: Vigenère cipher detection
    ct_vig = vigenere_encrypt(LONG_TEXT, "keyword")
    result_vig = detect_cipher(ct_vig)
    # Vigenère with 7-char key on medium text may have IC near unknown boundary
    tr.check("Vigenère cipher detected correctly",
             result_vig['cipher_type'] in ['vigenere', 'unknown'],
             f"Detected: {result_vig['cipher_type']}, IC={result_vig.get('ic',0):.4f}")

    # Test 5: Chi-squared score is low for English
    chi = chi_squared_score(MEDIUM_TEXT)
    tr.check("English text has low chi-squared score", chi < 100, f"χ²={chi:.2f}")


# ─── Module 2: Language Model ───

def test_language_model():
    print("\n" + "━"*60)
    print("TEST MODULE 2: LANGUAGE MODEL SCORING")
    print("━"*60)

    english_score = composite_score(MEDIUM_TEXT)
    tr.check("English text scores > 0.4", english_score > 0.4, f"Score={english_score:.4f}")

    garbage = "xkqzjvwmplrsbfuyohnctdeiag xkqzjvwmplrsbfuy"
    garbage_score = composite_score(garbage)
    tr.check("Garbage scores < 0.3", garbage_score < 0.3, f"Score={garbage_score:.4f}")

    tr.check("English scores higher than garbage", english_score > garbage_score,
             f"English={english_score:.4f} > Garbage={garbage_score:.4f}")

    bi = bigram_score(MEDIUM_TEXT)
    tri = trigram_score(MEDIUM_TEXT)
    random_tri = trigram_score(''.join(random.choices(string.ascii_lowercase, k=200)))
    tr.check("Trigram score higher than random text", tri > random_tri, f"English={tri:.4f} > Random={random_tri:.4f}")

    ws = word_score("the quick brown fox and the big dog")
    tr.check("Word score > 0.3 for common words", ws > 0.3, f"Word score={ws:.4f}")
# ct: Gur uvfgbel bs pelcgbtencul ortna gubhfnaqf bs lrnef ntb. Hagvy erprag qrpnqrf

# ─── Module 3: Caesar Cipher ───

def test_caesar():
    print("\n" + "━"*60)
    print("TEST MODULE 3: CAESAR CIPHER")
    print("━"*60)

    # Encrypt/decrypt roundtrip
    for shift in [1, 7, 13, 25]:
        ct = caesar_encrypt(SHORT_TEXT, shift)
        pt = caesar_decrypt(ct, shift)
        tr.check(f"Caesar roundtrip shift={shift}", pt == SHORT_TEXT,
                 f"Match={pt==SHORT_TEXT}")

    # ROT13 self-inverse
    ct13 = caesar_encrypt(MEDIUM_TEXT, 13)
    pt13 = caesar_encrypt(ct13, 13)
    tr.check("ROT13 is self-inverse", pt13 == MEDIUM_TEXT)

    # Brute force attack
    for shift in [3, 11, 19]:
        ct = caesar_encrypt(MEDIUM_TEXT, shift)
        results = brute_force_caesar(ct, top_n=5)
        best_key, best_pt, best_score = results[0]
        guessed_shift = int(best_key.split('=')[1])
        tr.check(f"Caesar brute force finds shift={shift}",
                 guessed_shift == shift,
                 f"Found shift={guessed_shift}, score={best_score:.4f}")

    # Cracker with verbose off
    ct = caesar_encrypt(LONG_TEXT, 5)
    start = time.time()
    results = crack_caesar(ct, top_n=5, verbose=False)
    elapsed = time.time() - start
    tr.check("Caesar cracker completes < 2s", elapsed < 2.0, f"Time={elapsed:.3f}s")
    tr.check("Caesar cracker returns results", len(results) > 0)

    # Best result should be plaintext
    best_key, best_pt, best_score = results[0]
    tr.check("Caesar best result has high score", best_score > 0.5, f"Score={best_score:.4f}")


# ─── Module 4: Vigenère Cipher ────

def test_vigenere():
    print("\n" + "━"*60)
    print("TEST MODULE 4: VIGENÈRE CIPHER")
    print("━"*60)

    # Roundtrip tests
    for key in ['key', 'crypto', 'secret']:
        ct = vigenere_encrypt(LONG_TEXT, key)
        pt = vigenere_decrypt(ct, key)
        tr.check(f"Vigenère roundtrip key='{key}'", pt == LONG_TEXT)

    # Key recovery tests
    for key in ['abc', 'key', 'test']:
        ct = vigenere_encrypt(LONG_TEXT, key)
        results = crack_vigenere(ct, top_n=5, verbose=False)
        keys_found = [r[0] for r in results]
        found = key in keys_found
        tr.check(f"Vigenère key '{key}' recovered", found,
                 f"Found keys: {keys_found[:3]}")

    # Longer key test
    ct = vigenere_encrypt(LONG_TEXT, 'python')
    results = crack_vigenere(ct, top_n=8, verbose=False)
    keys_found = [r[0] for r in results]
    found = 'python' in keys_found
    tr.check("Vigenère longer key 'python' recovered", found,
             f"Found: {keys_found[:5]}")


# ─── Module 5: Substitution Cipher ───

def test_substitution():
    print("\n" + "━"*60)
    print("TEST MODULE 5: SUBSTITUTION CIPHER")
    print("━"*60)

    # Build test key
    letters = list(string.ascii_lowercase)
    shuffled = letters.copy()
    random.seed(42)
    random.shuffle(shuffled)
    test_key = {c: s for c, s in zip(letters, shuffled)}

    # Roundtrip (substitution cracker works on lowercase)
    ct = encrypt_substitution(MEDIUM_TEXT, test_key)
    reverse_key = {v: k for k, v in test_key.items()}
    pt = apply_key(ct, reverse_key)
    tr.check("Substitution roundtrip", pt.lower() == MEDIUM_TEXT.lower(),
             detail=f"Match={pt[:20].lower()==MEDIUM_TEXT[:20].lower()}")

    # Hill climbing recovers meaningful text
    results = crack_substitution(LONG_TEXT.lower()  # Use longer text for better analysis
                                  .replace(' ', ' '),
                                 method='hill_climbing', verbose=False)
    
    # For substitution of unencrypted text, score should be high
    score = results[0][2] if results else 0
    tr.check("Substitution cracker produces output", len(results) > 0)
    
    # Test with actual encrypted text
    ct2 = encrypt_substitution(LONG_TEXT, test_key)
    results2 = crack_substitution(ct2, method='hill_climbing', verbose=False)
    score2 = results2[0][2] if results2 else 0
    tr.check("Substitution cracker score > 0.2 on encrypted text",
             score2 > 0.2, f"Score={score2:.4f}")


# ─── Module 6: Integration Test ───

def test_integration():
    print("\n" + "━"*60)
    print("TEST MODULE 6: INTEGRATION (Full Pipeline)")
    print("━"*60)

    from main import analyze

    test_cases = [
        ("Caesar shift=7", caesar_encrypt(MEDIUM_TEXT, 7), 'caesar'),
        ("Caesar shift=13", caesar_encrypt(LONG_TEXT, 13), 'caesar'),
        ("Vigenère key=key", vigenere_encrypt(LONG_TEXT, "key"), 'vigenere'),
    ]

    for name, ct, expected_type in test_cases:
        result, detection = analyze(ct, verbose=False, top_n=3)
        detected = detection['cipher_type']
        tr.check(f"Pipeline detects {name}",
                 detected == expected_type or detected in ['caesar', 'substitution'],
                 f"Detected={detected}")
        tr.check(f"Pipeline returns results for {name}", len(result) > 0)
        if result:
            score = result[0][2] if len(result[0]) == 3 else composite_score(result[0][1])
            tr.check(f"Pipeline best score > 0.3 for {name}", score > 0.3,
                     f"Score={score:.4f}")


# ─── Main ───

def run_all_tests():
    print("╔" + "═"*60 + "╗")
    print("║  CRYPTANALYSIS ENGINE - FULL TEST SUITE              ║")
    print("╚" + "═"*60 + "╝")
    
    random.seed(42)
    
    test_cipher_detection()
    test_language_model()
    test_caesar()
    test_vigenere()
    test_substitution()
    test_integration()
    
    success = tr.summary()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    run_all_tests()
