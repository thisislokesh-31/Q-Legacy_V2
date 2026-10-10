from contextlib import asynccontextmanager
import json
import os
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, UploadFile, File, HTTPException, Path, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles


def parse_cors_origins(raw_value: Optional[str]) -> List[str]:
    if raw_value:
        origins = [origin.strip() for origin in raw_value.split(",") if origin.strip()]
        if origins:
            return origins
    return ["http://localhost:8000", "http://127.0.0.1:8000"]


def require_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    expected_key = os.getenv("QLEGACY_API_KEY")
    if expected_key is None:
        return None
    if not x_api_key or x_api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return x_api_key


try:
    from .database import get_connection, initialize_database
    from .models import (
        AssetCreate,
        AssetResponse,
        AESEncryptRequest,
        AESEncryptResponse,
        AESDecryptRequest,
        AESDecryptResponse,
        MLKEMEncapsRequest,
        MLKEMEncapsResponse,
        MLKEMDecapsRequest,
        MLKEMDecapsResponse,
    )
    from .risk_engine import analyze_asset_content, assess_single_algorithm
    from .crypto_aes import (
        generate_aes256_key,
        encrypt_aes256_gcm,
        decrypt_aes256_gcm,
        run_aes_demo,
    )
    from .crypto_mlkem import (
        generate_mlkem_keypair,
        encapsulate_mlkem,
        decapsulate_mlkem,
        run_mlkem_demo,
    )
except ImportError:  # pragma: no cover - fallback when run as a standalone module
    from database import get_connection, initialize_database
    from models import (
        AssetCreate,
        AssetResponse,
        AESEncryptRequest,
        AESEncryptResponse,
        AESDecryptRequest,
        AESDecryptResponse,
        MLKEMEncapsRequest,
        MLKEMEncapsResponse,
        MLKEMDecapsRequest,
        MLKEMDecapsResponse,
    )
    from risk_engine import analyze_asset_content, assess_single_algorithm
    from crypto_aes import (
        generate_aes256_key,
        encrypt_aes256_gcm,
        decrypt_aes256_gcm,
        run_aes_demo,
    )
    from crypto_mlkem import (
        generate_mlkem_keypair,
        encapsulate_mlkem,
        decapsulate_mlkem,
        run_mlkem_demo,
    )

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB limit


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-initialize SQLite database on startup
    initialize_database()
    yield


app = FastAPI(
    title="Q-Legacy Backend API",
    description="Quantum-Safe Digital Asset Lifecycle Platform & Migration Assessment Engine",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS for local frontend access while avoiding a wildcard default.
app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(os.getenv("CORS_ORIGINS")),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# --------------------------------------------------
# Phase 1 & 6: Root UI, Health & Documentation
# --------------------------------------------------

@app.get("/", tags=["Frontend"])
@app.get("/dashboard", tags=["Frontend"], include_in_schema=False)
def serve_ui():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {
        "project": "Q-Legacy",
        "tagline": "Quantum-Safe Digital Asset Lifecycle Platform",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health():
    return {
        "status": "healthy",
        "database": "connected",
        "pqc_engine": "active",
    }


# --------------------------------------------------
# Phase 2 & 3: Asset Analysis & Lifecycle APIs
# --------------------------------------------------

@app.post(
    "/api/analyze",
    tags=["Asset Assessment"],
    summary="Analyze an uploaded digital asset for classical and PQC cryptographic primitives",
)
@app.post("/analyze", tags=["Asset Assessment"], include_in_schema=False)
async def analyze_asset(file: UploadFile = File(...), api_key: Optional[str] = Depends(require_api_key)):
    if not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file uploaded.",
        )

    content = await file.read(MAX_FILE_SIZE + 1)

    if not content or len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File content is empty.",
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE // (1024 * 1024)} MB.",
        )

    filename = file.filename or "uploaded_asset"
    assessment = analyze_asset_content(filename, content)
    return assessment


@app.post(
    "/api/assets",
    status_code=status.HTTP_201_CREATED,
    response_model=AssetResponse,
    tags=["Asset Management"],
    summary="Register an asset in the inventory",
)
def register_asset(asset: AssetCreate, api_key: Optional[str] = Depends(require_api_key)):
    # Evaluate algorithms if risk parameters not directly supplied
    algorithms = [algo.upper().strip() for algo in asset.algorithms]

    if asset.risk_level and asset.recommendation:
        risk = asset.risk_level.upper()
        recommendation = asset.recommendation
        priority = asset.priority or "MEDIUM"
        confidence = asset.confidence or "MEDIUM"
    else:
        # Determine using risk engine rules
        if any(a in {"RSA", "ECDSA", "ECDH", "EC", "DSA", "ED25519", "ED448"} for a in algorithms):
            risk = "HIGH"
            priority = "HIGH"
            confidence = "HIGH"
            recommendation = "Plan migration to post-quantum standards (ML-KEM, ML-DSA)."
        elif any(a in {"ML-KEM", "ML-DSA", "SLH-DSA"} for a in algorithms):
            risk = "PQC"
            priority = "LOW"
            confidence = "HIGH"
            recommendation = "Asset uses standardized post-quantum algorithm."
        elif any(a in {"AES-256", "AES-256-GCM", "CHACHA20"} for a in algorithms):
            risk = "LOWER"
            priority = "LOW"
            confidence = "HIGH"
            recommendation = "Symmetric encryption in use. Maintain key rotation and secure IVs."
        else:
            risk = "UNKNOWN"
            priority = "MEDIUM"
            confidence = "LOW"
            recommendation = "Review asset and identify cryptographic implementation details."

    details_json = json.dumps(asset.details or {})
    algorithms_json = json.dumps(algorithms)
    evidence_json = json.dumps(asset.evidence or [])
    manual_review_required = bool(asset.manual_review_required)

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO assets
            (filename, asset_type, algorithms, risk_level, recommendation, confidence, priority, manual_review_required, evidence, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset.filename,
                asset.asset_type,
                algorithms_json,
                risk,
                recommendation,
                confidence,
                priority,
                manual_review_required,
                evidence_json,
                details_json,
            ),
        )
        asset_id = cursor.lastrowid
        conn.commit()

        # Fetch created row
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()

    return row_to_asset_dict(row)


@app.get(
    "/api/assets",
    response_model=List[AssetResponse],
    tags=["Asset Management"],
    summary="List all registered assets in inventory",
)
def list_assets(api_key: Optional[str] = Depends(require_api_key)):
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM assets ORDER BY id DESC").fetchall()

    return [row_to_asset_dict(row) for row in rows]


@app.get(
    "/api/assets/{asset_id}",
    response_model=AssetResponse,
    tags=["Asset Management"],
    summary="Retrieve details of a single registered asset",
)
def get_asset(asset_id: int = Path(..., ge=1), api_key: Optional[str] = Depends(require_api_key)):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found.",
        )

    return row_to_asset_dict(row)


@app.delete(
    "/api/assets/{asset_id}",
    tags=["Asset Management"],
    summary="Delete an asset from the inventory",
)
def delete_asset(asset_id: int = Path(..., ge=1), api_key: Optional[str] = Depends(require_api_key)):
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset with ID {asset_id} not found.",
            )

    return {"message": f"Asset {asset_id} successfully deleted."}


@app.get(
    "/api/dashboard",
    tags=["Dashboard Metrics"],
    summary="Get aggregated asset inventory metrics and quantum risk statistics",
)
def get_dashboard_metrics(api_key: Optional[str] = Depends(require_api_key)):
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM assets").fetchall()

    total_assets = len(rows)
    risk_distribution = {
        "HIGH": 0,
        "LOWER": 0,
        "PQC": 0,
        "UNKNOWN": 0,
    }
    priority_distribution = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFORMATIONAL": 0,
    }

    for row in rows:
        r_level = row["risk_level"] if row["risk_level"] in risk_distribution else "UNKNOWN"
        p_level = row["priority"] if row["priority"] in priority_distribution else "MEDIUM"
        risk_distribution[r_level] += 1
        priority_distribution[p_level] += 1

    quantum_vulnerable_count = risk_distribution["HIGH"]
    quantum_safe_count = risk_distribution["PQC"] + risk_distribution["LOWER"]
    quantum_readiness_percentage = (
        round((quantum_safe_count / total_assets) * 100, 1) if total_assets > 0 else 100.0
    )

    return {
        "total_assets": total_assets,
        "quantum_vulnerable_count": quantum_vulnerable_count,
        "quantum_safe_count": quantum_safe_count,
        "quantum_readiness_percentage": quantum_readiness_percentage,
        "risk_distribution": risk_distribution,
        "priority_distribution": priority_distribution,
        "migration_summary": {
            "critical_action_required": quantum_vulnerable_count > 0,
            "recommended_next_step": (
                f"Migrate {quantum_vulnerable_count} high-risk assets using NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)."
                if quantum_vulnerable_count > 0
                else "All inventoried assets currently meet baseline quantum resilience."
            ),
        },
    }


# --------------------------------------------------
# Phase 4: AES-256-GCM Endpoints
# --------------------------------------------------

@app.get("/api/crypto/aes/demo", tags=["Cryptography - AES-256-GCM"])
def aes_demo():
    """Runs a complete AES-256-GCM encryption, decryption, and tamper rejection demo."""
    return run_aes_demo()


@app.post(
    "/api/crypto/aes/encrypt",
    response_model=AESEncryptResponse,
    tags=["Cryptography - AES-256-GCM"],
)
def aes_encrypt(req: AESEncryptRequest):
    try:
        if req.key_hex:
            key = bytes.fromhex(req.key_hex)
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes (64 hex characters).")
        else:
            key = generate_aes256_key()

        nonce, ciphertext = encrypt_aes256_gcm(req.plaintext.encode("utf-8"), key)

        return AESEncryptResponse(
            key_hex=key.hex(),
            nonce_hex=nonce.hex(),
            ciphertext_hex=ciphertext.hex(),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"AES Encryption error: {str(e)}",
        )


@app.post(
    "/api/crypto/aes/decrypt",
    response_model=AESDecryptResponse,
    tags=["Cryptography - AES-256-GCM"],
)
def aes_decrypt(req: AESDecryptRequest):
    try:
        key = bytes.fromhex(req.key_hex)
        nonce = bytes.fromhex(req.nonce_hex)
        ciphertext = bytes.fromhex(req.ciphertext_hex)

        plaintext_bytes = decrypt_aes256_gcm(ciphertext, key, nonce)
        return AESDecryptResponse(
            plaintext=plaintext_bytes.decode("utf-8", errors="ignore"),
            authentic=True,
            status="Decryption successful. Authentication tag verified.",
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"AES Decryption error: {str(e)}",
        )


# --------------------------------------------------
# Phase 5: ML-KEM (NIST FIPS 203) Endpoints
# --------------------------------------------------

@app.get("/api/crypto/mlkem/demo", tags=["Cryptography - ML-KEM-768"])
def mlkem_demo():
    """Runs a complete ML-KEM-768 Key Encapsulation and Decapsulation demonstration."""
    return run_mlkem_demo()


@app.post("/api/crypto/mlkem/keygen", tags=["Cryptography - ML-KEM-768"])
def mlkem_keygen():
    """Generates an ML-KEM-768 (NIST FIPS 203) public and secret key pair in hexadecimal format."""
    pk, sk = generate_mlkem_keypair()
    return {
        "algorithm": "ML-KEM-768 (NIST FIPS 203)",
        "public_key_hex": pk.hex(),
        "secret_key_hex": sk.hex(),
        "public_key_bytes": len(pk),
        "secret_key_bytes": len(sk),
    }


@app.post(
    "/api/crypto/mlkem/encapsulate",
    response_model=MLKEMEncapsResponse,
    tags=["Cryptography - ML-KEM-768"],
)
def mlkem_encapsulate(req: MLKEMEncapsRequest):
    try:
        pk = bytes.fromhex(req.public_key_hex)
        ciphertext, shared_secret = encapsulate_mlkem(pk)
        return MLKEMEncapsResponse(
            ciphertext_hex=ciphertext.hex(),
            shared_secret_hex=shared_secret.hex(),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ML-KEM Encapsulation failed: {str(e)}",
        )


@app.post(
    "/api/crypto/mlkem/decapsulate",
    response_model=MLKEMDecapsResponse,
    tags=["Cryptography - ML-KEM-768"],
)
def mlkem_decapsulate(req: MLKEMDecapsRequest):
    try:
        sk = bytes.fromhex(req.secret_key_hex)
        ciphertext = bytes.fromhex(req.ciphertext_hex)
        shared_secret = decapsulate_mlkem(sk, ciphertext)
        return MLKEMDecapsResponse(
            shared_secret_hex=shared_secret.hex(),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ML-KEM Decapsulation failed: {str(e)}",
        )


# Helper function to format Row dict safely
def row_to_asset_dict(row) -> dict:
    if not row:
        return {}
    d = dict(row)
    try:
        d["algorithms"] = json.loads(d.get("algorithms", "[]"))
    except Exception:
        d["algorithms"] = []

    try:
        d["evidence"] = json.loads(d.get("evidence", "[]"))
    except Exception:
        d["evidence"] = []

    try:
        d["details"] = json.loads(d.get("details", "{}"))
    except Exception:
        d["details"] = {}

    d["confidence"] = d.get("confidence") or "MEDIUM"
    d["priority"] = d.get("priority") or "MEDIUM"
    d["manual_review_required"] = bool(d.get("manual_review_required") in (1, "1", True, "true", "True"))
    d["risk_level"] = d.get("risk_level") or "UNKNOWN"
    d["recommendation"] = d.get("recommendation") or ""
    return d
