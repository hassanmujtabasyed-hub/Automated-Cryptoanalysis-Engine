"""
Automated Cryptanalysis Engine
Main orchestrator that detects cipher type and applies appropriate
cryptanalysis technique automatically.

Usage:
    python main.py
    python main.py --text "your ciphertext here"
    python main.py --demo
"""

import sys
import os
import argparse
import time

# Add the module directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cipher_detection import detect_cipher, index_of_coincidence, chi_squared_score
from language_model import composite_score, rank_candidates
from caesar_cracker import crack_caesar
from substitution_cracker import crack_substitution
from vigenere_cracker import crack_vigenere


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          AUTOMATED CRYPTANALYSIS ENGINE                      ║
║          Classical Cipher Breaker v1.0                       ║
║          Course: Information Security                        ║
╚══════════════════════════════════════════════════════════════╝
"""


def analyze(ciphertext, verbose=True, top_n=5):
    """
    Full pipeline:
    1. Detect cipher type
    2. Apply cryptanalysis
    3. Return ranked results
    """
    if verbose:
        print(BANNER)
    
    print(f"[INPUT] Ciphertext ({len(ciphertext)} chars):")
    print(f"  {ciphertext[:100]}{'...' if len(ciphertext)>100 else ''}")
    print()

    # ─── STAGE 1: CIPHER DETECTION ───
    print("━"*60)
    print("STAGE 1: CIPHER DETECTION")
    print("━"*60)
    
    detection = detect_cipher(ciphertext)
    cipher_type = detection['cipher_type']
    confidence = detection.get('confidence', 0)
    ic = detection.get('ic', 0)
    chi = detection.get('chi', 0)

    print(f"  Detected Cipher   : {cipher_type.upper()}")
    print(f"  Confidence        : {confidence*100:.1f}%")
    print(f"  Index of Coincidence: {ic:.4f}")
    print(f"  Chi-Squared Score : {chi:.2f}")
    for note in detection.get('notes', []):
        print(f"  • {note}")

    # ─── STAGE 2: CRYPTANALYSIS ──
    print()
    print("━"*60)
    print("STAGE 2: CRYPTANALYSIS ENGINE")
    print("━"*60)

    start_time = time.time()
    results = []

    if cipher_type == 'caesar':
        results = crack_caesar(ciphertext, top_n=top_n, verbose=verbose)
    elif cipher_type == 'substitution':
        results = crack_substitution(ciphertext, method='hill_climbing', verbose=verbose)
    elif cipher_type == 'vigenere':
        results = crack_vigenere(ciphertext, top_n=top_n, verbose=verbose)
    else:
        print(f"  [!] Unknown cipher type. Trying Caesar as fallback...")
        results = crack_caesar(ciphertext, top_n=top_n, verbose=verbose)

    elapsed = time.time() - start_time

    # ─── STAGE 3: OUTPUT RANKING ──
    print()
    print("━"*60)
    print("STAGE 3: RANKED OUTPUT")
    print("━"*60)
    print(f"  Analysis completed in {elapsed:.2f}s")
    print(f"  Cipher type: {cipher_type.upper()} (confidence: {confidence*100:.1f}%)")
    print()

    if results:
        print(f"  TOP {min(top_n, len(results))} DECRYPTION CANDIDATES:")
        print("  " + "─"*56)
        for i, result in enumerate(results[:top_n], 1):
            if len(result) == 3:
                key, plaintext, score = result
            else:
                key, plaintext = result[0], result[1]
                score = composite_score(plaintext)
            
            confidence_label = "HIGH" if score > 0.6 else "MEDIUM" if score > 0.35 else "LOW"
            print(f"  #{i} [{confidence_label}] Score: {score:.4f}  Key: {key}")
            print(f"     Text: {plaintext[:80]}{'...' if len(plaintext)>80 else ''}")
            print()

        best_key, best_pt, best_score = (results[0] if len(results[0])==3
                                          else (results[0][0], results[0][1],
                                                composite_score(results[0][1])))
        print("  " + "─"*56)
        print("  ★ BEST CANDIDATE:")
        print(f"     Key: {best_key}")
        print(f"     Score: {best_score:.4f}")
        print(f"     Plaintext:\n")
        print(f"     {best_pt}")
    else:
        print("  No results found.")

    print()
    return results, detection


def run_demo():
    """Run demonstration with known examples."""
    
    print(BANNER)
    
    # Import encryption functions for demo
    from caesar_cracker import caesar_encrypt
    from vigenere_cracker import vigenere_encrypt
    from substitution_cracker import encrypt_substitution
    import random
    import string

    demos = []

    # Demo 1: Caesar Cipher
    pt1 = "The enemy will attack at dawn. Prepare your defenses and alert all troops immediately."
    ct1 = caesar_encrypt(pt1, 7)
    demos.append(("CAESAR CIPHER DEMO", ct1, pt1, "shift=7"))

    # Demo 2: Vigenère Cipher
    pt2 = ("Cryptography is the practice of securing communication from adversaries. "
           "The Vigenere cipher uses a keyword to shift each letter differently, "
           "making simple frequency analysis insufficient to break it.")
    ct2 = vigenere_encrypt(pt2, "secret")
    demos.append(("VIGENÈRE CIPHER DEMO", ct2, pt2, "key=secret"))

    for title, ciphertext, original, key_info in demos:
        print("\n" + "╔" + "═"*60 + "╗")
        print(f"║ {title:<58} ║")
        print("╚" + "═"*60 + "╝")
        print(f"  Original plaintext: {original[:70]}...")
        print(f"  True key: {key_info}")
        print(f"  Ciphertext: {ciphertext[:70]}...")
        
        analyze(ciphertext, verbose=False, top_n=3)
        print()
        input("  [Press ENTER to continue to next demo...]\n")


def main():
    parser = argparse.ArgumentParser(
        description='Automated Cryptanalysis Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo
  python main.py --text "Wkh txlfn eurzq ira"
  python main.py --text "LZMSZ FMKFZ" --cipher vigenere
  python main.py --interactive
        """
    )
    parser.add_argument('--text', '-t', type=str, help='Ciphertext to analyze')
    parser.add_argument('--cipher', '-c', type=str, choices=['auto', 'caesar', 'substitution', 'vigenere'],
                        default='auto', help='Force cipher type (default: auto-detect)')
    parser.add_argument('--demo', '-d', action='store_true', help='Run demonstration mode')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--top', '-n', type=int, default=5, help='Number of top results to show')

    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if args.interactive:
        print(BANNER)
        print("Interactive Cryptanalysis Mode")
        print("Commands: analyze, encrypt, quit\n")
        
        while True:
            cmd = input("Enter command (analyze/encrypt/quit): ").strip().lower()
            
            if cmd == 'quit':
                print("Goodbye!")
                break
            elif cmd == 'analyze':
                ct = input("Enter ciphertext: ").strip()
                if ct:
                    analyze(ct, top_n=args.top)
            elif cmd == 'encrypt':
                pt = input("Enter plaintext: ").strip()
                cipher = input("Cipher (caesar/vigenere): ").strip().lower()
                if cipher == 'caesar':
                    from caesar_cracker import caesar_encrypt
                    shift = int(input("Enter shift (0-25): "))
                    print(f"Encrypted: {caesar_encrypt(pt, shift)}")
                elif cipher == 'vigenere':
                    from vigenere_cracker import vigenere_encrypt
                    key = input("Enter keyword: ").strip()
                    print(f"Encrypted: {vigenere_encrypt(pt, key)}")
                else:
                    print("Unknown cipher.")
            else:
                print("Unknown command.")
        return

    if args.text:
        analyze(args.text, top_n=args.top)
        return

    # Default: show usage and run a quick example
    print(BANNER)
    print("No input provided. Running quick example...\n")
    example_ct = "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"
    print(f"Example ciphertext: {example_ct}")
    print("(This is 'The quick brown fox jumps over the lazy dog' encrypted with Caesar shift=3)\n")
    analyze(example_ct, top_n=3)


if __name__ == "__main__":
    main()
