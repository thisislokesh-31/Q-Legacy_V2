import pqcrypto.kem.ml_kem_768 as ml_kem_768
from typing import Dict, Any, Tuple


def generate_mlkem_keypair() -> Tuple[bytes, bytes]:
    """
    Generates an ML-KEM-768 (NIST FIPS 203) keypair.
    Returns (public_key, secret_key).
    - Public key length: 1184 bytes
    - Secret key length: 2400 bytes
    """
    pk, sk = ml_kem_768.keygen()
    return pk, sk


def encapsulate_mlkem(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulates a random 256-bit shared secret using the recipient's public key.
    Returns (ciphertext, shared_secret).
    - Ciphertext length: 1088 bytes
    - Shared secret length: 32 bytes (256 bits)
    """
    if len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-768 public key size. Expected {ml_kem_768.PUBLIC_KEY_SIZE} bytes, got {len(public_key)} bytes."
        )
    ciphertext, shared_secret = ml_kem_768.encaps(public_key)
    return ciphertext, shared_secret


def decapsulate_mlkem(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulates the ciphertext using the recipient's secret key to recover the shared secret.
    Returns shared_secret (32 bytes).
    """
    if len(secret_key) != ml_kem_768.SECRET_KEY_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-768 secret key size. Expected {ml_kem_768.SECRET_KEY_SIZE} bytes, got {len(secret_key)} bytes."
        )
    if len(ciphertext) != ml_kem_768.CIPHERTEXT_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-768 ciphertext size. Expected {ml_kem_768.CIPHERTEXT_SIZE} bytes, got {len(ciphertext)} bytes."
        )

    shared_secret = ml_kem_768.decaps(secret_key, ciphertext)
    return shared_secret


def run_mlkem_demo() -> Dict[str, Any]:
    """Runs a complete end-to-end demonstration of ML-KEM-768 Key Encapsulation and Decapsulation."""
    # Step 1: Recipient generates keypair
    pk, sk = generate_mlkem_keypair()

    # Step 2: Sender encapsulates a shared secret using recipient's public key
    ciphertext, shared_secret_sender = encapsulate_mlkem(pk)

    # Step 3: Recipient decapsulates ciphertext using recipient's secret key
    shared_secret_recipient = decapsulate_mlkem(sk, ciphertext)

    # Step 4: Verification
    shared_secrets_match = (shared_secret_sender == shared_secret_recipient)

    return {
        "standard": "NIST FIPS 203",
        "algorithm": "ML-KEM-768 (Module-Lattice-Based Key-Encapsulation Mechanism)",
        "key_sizes": {
            "public_key_bytes": len(pk),
            "secret_key_bytes": len(sk),
            "ciphertext_bytes": len(ciphertext),
            "shared_secret_bytes": len(shared_secret_sender),
        },
        "simulation": {
            "recipient_public_key_hex_truncated": pk.hex()[:64] + "...",
            "ciphertext_hex_truncated": ciphertext.hex()[:64] + "...",
            "sender_derived_shared_secret_hex": shared_secret_sender.hex(),
            "recipient_derived_shared_secret_hex": shared_secret_recipient.hex(),
            "shared_secrets_identical": shared_secrets_match,
        },
        "educational_notes": {
            "kem_purpose": "ML-KEM is used for establishing a shared symmetric key over an insecure channel, NOT for bulk encryption or digital signatures.",
            "signatures_vs_kem": "Digital signatures (ML-DSA, SLH-DSA) provide authentication and non-repudiation. KEM (ML-KEM) provides post-quantum key agreement.",
            "hybrid_cryptography": "In production systems, ML-KEM derived shared secrets are typically used as key material for AES-256-GCM symmetric encryption.",
        },
    }
