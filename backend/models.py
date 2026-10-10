from typing import Any, List, Optional
from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255, description="Name of the asset file")
    asset_type: str = Field(default="unknown", max_length=100, description="Type of asset (e.g., X.509 certificate, Config, Source code)")
    algorithms: List[str] = Field(default_factory=list, description="List of detected cryptographic algorithm names")
    risk_level: Optional[str] = Field(default=None, description="Risk level (HIGH, LOWER, PQC, UNKNOWN)")
    recommendation: Optional[str] = Field(default=None, description="Actionable recommendation")
    confidence: Optional[str] = Field(default="MEDIUM", description="Confidence level (HIGH, MEDIUM, LOW)")
    priority: Optional[str] = Field(default="MEDIUM", description="Migration priority (HIGH, MEDIUM, LOW, INFORMATIONAL)")
    manual_review_required: bool = Field(default=False, description="Whether a human review is required before migration decisions are finalized.")
    evidence: List[dict[str, Any]] = Field(default_factory=list, description="Evidence collected for the detected cryptographic findings.")
    details: Optional[dict[str, Any]] = Field(default_factory=dict, description="Metadata and breakdown details")


class AssetResponse(BaseModel):
    id: int
    filename: str
    asset_type: str
    algorithms: List[str]
    risk_level: str
    recommendation: str
    confidence: str
    priority: str
    manual_review_required: bool
    evidence: List[dict[str, Any]]
    details: dict[str, Any]
    created_at: str


class AESEncryptRequest(BaseModel):
    plaintext: str = Field(..., min_length=1, description="Text content to encrypt using AES-256-GCM")
    key_hex: Optional[str] = Field(default=None, description="Optional 64-char hex key (256-bit). If omitted, a secure key is generated.")


class AESEncryptResponse(BaseModel):
    key_hex: str = Field(..., description="256-bit key in hexadecimal format")
    nonce_hex: str = Field(..., description="Unique 96-bit nonce in hexadecimal format")
    ciphertext_hex: str = Field(..., description="Encrypted payload and authentication tag in hexadecimal format")
    algorithm: str = "AES-256-GCM"
    note: str = "Key storage must be kept separate from ciphertext in production systems."


class AESDecryptRequest(BaseModel):
    key_hex: str = Field(..., min_length=64, max_length=64, description="256-bit key in hexadecimal format")
    nonce_hex: str = Field(..., min_length=24, max_length=24, description="96-bit nonce in hexadecimal format")
    ciphertext_hex: str = Field(..., min_length=1, description="Ciphertext with tag in hexadecimal format")


class AESDecryptResponse(BaseModel):
    plaintext: str
    authentic: bool = True
    status: str = "Decryption successful and authentication tag verified."


class MLKEMEncapsRequest(BaseModel):
    public_key_hex: str = Field(..., description="Public key of recipient in hex format (1184 bytes = 2368 hex chars)")


class MLKEMEncapsResponse(BaseModel):
    ciphertext_hex: str = Field(..., description="Encapsulated ciphertext (1088 bytes = 2176 hex chars)")
    shared_secret_hex: str = Field(..., description="Derived 256-bit shared secret (32 bytes = 64 hex chars)")
    algorithm: str = "ML-KEM-768 (NIST FIPS 203)"


class MLKEMDecapsRequest(BaseModel):
    secret_key_hex: str = Field(..., description="Secret key of recipient in hex format (2400 bytes = 4800 hex chars)")
    ciphertext_hex: str = Field(..., description="Encapsulated ciphertext in hex format (1088 bytes = 2176 hex chars)")


class MLKEMDecapsResponse(BaseModel):
    shared_secret_hex: str = Field(..., description="Decapsulated 256-bit shared secret (32 bytes = 64 hex chars)")
    algorithm: str = "ML-KEM-768 (NIST FIPS 203)"