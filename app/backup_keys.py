"""BIP39 recovery phrases for versioned, reproducible backup archive keys."""
import hashlib
import secrets
import unicodedata
from pathlib import Path

WORDS = (Path(__file__).parent / 'vendor' / 'bip39' / 'english.txt').read_text().splitlines()
WORD_IDS = {word: index for index, word in enumerate(WORDS)}
if len(WORDS) != 2048 or len(WORD_IDS) != 2048:
    raise RuntimeError('Invalid BIP39 wordlist')


def phrase_from_entropy(entropy):
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError('Invalid entropy length')
    checksum_bits = len(entropy) // 4
    value = (int.from_bytes(entropy, 'big') << checksum_bits) | (hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits))
    count = (len(entropy) * 8 + checksum_bits) // 11
    return ' '.join(WORDS[(value >> (11 * index)) & 2047] for index in reversed(range(count)))


def normalize_phrase(phrase):
    phrase = ' '.join(unicodedata.normalize('NFKD', phrase).lower().split())
    words = phrase.split()
    if len(words) not in (12, 15, 18, 21, 24) or any(word not in WORD_IDS for word in words):
        raise ValueError('Ungültige Wiederherstellungsphrase')
    value = 0
    for word in words:
        value = (value << 11) | WORD_IDS[word]
    checksum_bits = len(words) // 3
    entropy = (value >> checksum_bits).to_bytes((len(words) * 11 - checksum_bits) // 8, 'big')
    if phrase_from_entropy(entropy) != phrase:
        raise ValueError('Prüfsumme der Wiederherstellungsphrase stimmt nicht')
    return phrase


def seed(phrase, passphrase=''):
    phrase = normalize_phrase(phrase)
    salt = unicodedata.normalize('NFKD', 'mnemonic' + passphrase)
    return hashlib.pbkdf2_hmac('sha512', phrase.encode(), salt.encode(), 2048, dklen=64)


def archive_key(phrase):
    # A domain-separated archive password, followed by 7z's own AES-256 KDF.
    return hashlib.pbkdf2_hmac('sha512', seed(phrase), b'adfs-backup-archive-v1', 1, dklen=32).hex()


def generate():
    phrase = phrase_from_entropy(secrets.token_bytes(32))
    password = archive_key(phrase)
    return {'phrase': phrase, 'password': password, 'keyId': hashlib.sha256(password.encode()).hexdigest()[:24],
            'format': 'adfs-backup-archive-v1'}
