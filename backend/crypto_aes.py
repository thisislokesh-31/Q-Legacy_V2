import os
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def generate_aes256_key() -> bytes:
    """Generates a cryptographically secure 256-bit (32-byte) key for AES-GCM."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_aes256_gcm(plaintext: bytes, key: bytes, associated_data: bytes = None) -> Tuple[bytes, bytes]:
    """
    Encrypts plaintext using AES-256-GCM.
    Returns (nonce, ciphertext_with_tag).
    A fresh 96-bit (12-byte) nonce is generated for every encryption call.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes (256 bits).")

    aesgcm = AESGCM(key)
    # Generate fresh 96-bit nonce
    nonce = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext_with_tag


def decrypt_aes256_gcm(ciphertext_with_tag: bytes, key: bytes, nonce: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypts ciphertext and verifies authentication tag using AES-256-GCM.
    Raises ValueError if ciphertext or tag was tampered with.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes (256 bits).")
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes (96 bits).")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext
    except InvalidTag:
        raise ValueError("Decryption failed: Ciphertext or authentication tag has been tampered with.")


def run_aes_demo(sample_text: str = "Quantum-Safe Digital Asset Metadata") -> Dict[str, Any]:
    """Runs a complete demonstration of AES-256-GCM encryption, verification, and tamper rejection."""
    key = generate_aes256_key()
    plaintext_bytes = sample_text.encode("utf-8")

    # 1. Successful Encryption
    nonce, ciphertext = encrypt_aes256_gcm(plaintext_bytes, key)

    # 2. Successful Decryption
    decrypted_bytes = decrypt_aes256_gcm(ciphertext, key, nonce)
    success = (decrypted_bytes == plaintext_bytes)

    # 3. Tamper Test
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # Flip bits in first byte
    tamper_detected = False
    try:
        decrypt_aes256_gcm(bytes(tampered_ciphertext), key, nonce)
    except ValueError as e:
        tamper_detected = True
        tamper_msg = str(e)

    return {
        "algorithm": "AES-256-GCM",
        "key_bits": 256,
        "nonce_bits": 96,
        "key_hex": key.hex(),
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "plaintext": sample_text,
        "decrypted_plaintext": decrypted_bytes.decode("utf-8"),
        "decryption_verified": success,
        "tamper_test": {
            "tampered_ciphertext_hex": bytes(tampered_ciphertext).hex(),
            "tamper_rejected": tamper_detected,
            "error_message": tamper_msg if tamper_detected else "No error raised!",
        },
        "educational_notes": {
            "encryption": "AES-256-GCM provides confidentiality and integrity (AEAD). Grover's quantum search algorithm reduces key space to 128 bits, which remains secure.",
            "key_management": "Secret keys must be stored in secure Key Management Systems (KMS) or hardware security modules (HSM) separate from encrypted data.",
            "key_exchange": "AES-256-GCM requires a shared secret key. Key exchange across untrusted channels requires Post-Quantum KEM (like ML-KEM).",
        },
    }
