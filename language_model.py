"""
Language Scoring Module
Uses n-gram frequency models and word-based scoring to evaluate
how "English-like" a given text is.
"""

import math
from collections import Counter


# === Common English words for dictionary scoring ===
COMMON_WORDS = set([
    'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it',
    'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this',
    'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or',
    'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what',
    'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me',
    'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know',
    'take', 'people', 'into', 'year', 'your', 'good', 'some', 'could',
    'them', 'see', 'other', 'than', 'then', 'now', 'look', 'only', 'come',
    'its', 'over', 'think', 'also', 'back', 'after', 'use', 'two', 'how',
    'our', 'work', 'first', 'well', 'way', 'even', 'new', 'want', 'because',
    'any', 'these', 'give', 'day', 'most', 'us', 'is', 'are', 'was', 'were',
    'has', 'had', 'been', 'being', 'am', 'does', 'did', 'may', 'might',
    'shall', 'should', 'must', 'ought', 'need', 'dare', 'used', 'going',
    'here', 'where', 'every', 'great', 'little', 'long', 'big', 'down',
    'old', 'right', 'too', 'still', 'own', 'find', 'never', 'under', 'last',
    'life', 'point', 'world', 'very', 'hand', 'place', 'case', 'between',
    'tell', 'call', 'without', 'ask', 'same', 'each', 'turn', 'help', 'show',
    'again', 'off', 'much', 'before', 'move', 'play', 'small', 'number',
    'always', 'those', 'both', 'paper', 'together', 'got', 'group', 'often',
    'run', 'important', 'until', 'children', 'side', 'feet', 'car', 'mile',
    'night', 'walk', 'white', 'sea', 'began', 'grow', 'took', 'river',
    'four', 'carry', 'state', 'once', 'book', 'hear', 'stop', 'without',
    'second', 'late', 'miss', 'idea', 'body', 'light', 'voice', 'power',
    'town', 'fine', 'drive', 'short', 'road', 'true', 'above', 'oh', 'yes',
    'to', 'be', 'he', 'she', 'it', 'we', 'they', 'so', 'do',
    'message', 'secret', 'key', 'code', 'attack', 'cipher', 'plain', 'text'
])

# English letter frequencies
ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074
}

# Bigram frequencies (top English bigrams, approximate log-probs)
ENGLISH_BIGRAMS = {
    'th': 3.56, 'he': 3.07, 'in': 2.43, 'er': 2.05, 'an': 1.99,
    're': 1.85, 'on': 1.76, 'en': 1.75, 'at': 1.49, 'es': 1.40,
    'ed': 1.37, 'nd': 1.31, 'or': 1.28, 'to': 1.28, 'is': 1.27,
    'ti': 1.24, 'ha': 1.22, 'it': 1.20, 'ng': 0.89, 'st': 0.88,
    'io': 0.83, 've': 0.83, 'te': 0.82, 'hi': 0.80, 'as': 0.78,
    'ou': 0.76, 'se': 0.73, 'le': 0.71, 'of': 0.67, 'de': 0.65,
    'al': 0.64, 'li': 0.62, 'me': 0.62, 'ar': 0.58, 'ne': 0.57,
    'nt': 0.56, 'ea': 0.54, 'si': 0.54, 'ot': 0.52, 'ro': 0.52,
    'ow': 0.51, 'no': 0.50, 'ho': 0.49, 'ta': 0.49, 'ur': 0.48,
    'wh': 0.48, 'co': 0.47, 'fi': 0.45, 'ss': 0.45, 'tr': 0.44,
    'ac': 0.43, 'ay': 0.43, 'ce': 0.42, 'ec': 0.42, 'el': 0.42,
    'ly': 0.42, 'ma': 0.42, 'be': 0.40, 'ca': 0.40, 'fo': 0.40,
    'la': 0.40, 'pe': 0.38, 'pr': 0.38, 'ri': 0.38, 'sa': 0.37,
    'sh': 0.37, 'sp': 0.35, 'wi': 0.35, 'ba': 0.33, 'ge': 0.33,
    'ic': 0.32, 'ld': 0.32, 'ev': 0.31, 'wo': 0.30, 'ra': 0.29
}

# Trigram frequencies
ENGLISH_TRIGRAMS = {
    'the': 3.51, 'and': 1.59, 'ing': 1.15, 'ion': 0.95, 'ent': 0.87,
    'her': 0.80, 'for': 0.79, 'tha': 0.78, 'nth': 0.77, 'int': 0.73,
    'ere': 0.71, 'tio': 0.70, 'ter': 0.70, 'est': 0.68, 'res': 0.64,
    'ati': 0.64, 'his': 0.63, 'hat': 0.62, 'hin': 0.61, 'con': 0.57,
    'all': 0.54, 'ive': 0.54, 'nce': 0.53, 'men': 0.52, 'not': 0.52,
    'are': 0.50, 'was': 0.49, 'ect': 0.48, 'ant': 0.47, 'ith': 0.47
}


def chi_squared_score(text):
    """Chi-squared vs English. Lower is better."""
    from collections import Counter
    import re
    text = re.sub(r'[^a-z]', '', text.lower())
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


def bigram_score(text):
    """Score based on bigram frequencies. Higher is better."""
    import re
    text = re.sub(r'[^a-z]', '', text.lower())
    score = 0.0
    for i in range(len(text) - 1):
        bg = text[i:i+2]
        score += ENGLISH_BIGRAMS.get(bg, -2.0)
    return score / max(len(text) - 1, 1)


def trigram_score(text):
    """Score based on trigram frequencies. Higher is better."""
    import re
    text = re.sub(r'[^a-z]', '', text.lower())
    score = 0.0
    for i in range(len(text) - 2):
        tg = text[i:i+3]
        score += ENGLISH_TRIGRAMS.get(tg, -3.0)
    return score / max(len(text) - 2, 1)


def word_score(text):
    """Fraction of recognized English words. Higher is better."""
    import re
    words = re.findall(r'[a-z]+', text.lower())
    if not words:
        return 0.0
    matched = sum(1 for w in words if w in COMMON_WORDS)
    return matched / len(words)


def composite_score(text):
    """
    Composite "Englishness" score combining multiple metrics.
    Returns a normalized score: higher = more English-like.
    """
    if not text or len(text.strip()) == 0:
        return 0.0

    chi = chi_squared_score(text)
    chi_norm = max(0, 1 - chi / 500)  # normalize chi-squared

    bi = bigram_score(text)
    bi_norm = (bi + 3) / 5  # shift to 0-1 range roughly

    tri = trigram_score(text)
    tri_norm = (tri + 3) / 5

    word = word_score(text)

    # Weighted combination
    score = (
        0.30 * chi_norm +
        0.25 * bi_norm +
        0.20 * tri_norm +
        0.25 * word
    )
    return max(0.0, min(1.0, score))


def rank_candidates(candidates):
    """
    Given a list of (key, plaintext) tuples, rank by composite score.
    Returns sorted list of (key, plaintext, score) descending.
    """
    scored = []
    for key, plaintext in candidates:
        score = composite_score(plaintext)
        scored.append((key, plaintext, score))
    scored.sort(key=lambda x: x[2], reverse=True)
    return scored
