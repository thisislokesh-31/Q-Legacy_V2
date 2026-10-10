from typing import Any, Dict, List, Tuple

QUANTUM_VULNERABLE_ALGORITHMS = {
    "RSA": {
        "family": "Asymmetric / Public Key Encryption & Signatures",
        "description": "Factorization-based asymmetric algorithm.",
        "quantum_threat": "Vulnerable to Shor's algorithm running on CRQCs (Cryptographically Relevant Quantum Computers).",
    },
    "ECDSA": {
        "family": "Elliptic Curve Digital Signature",
        "description": "Discrete logarithm-based signature algorithm.",
        "quantum_threat": "Vulnerable to Shor's algorithm on quantum hardware.",
    },
    "ECDH": {
        "family": "Elliptic Curve Diffie-Hellman Key Exchange",
        "description": "Elliptic curve key agreement.",
        "quantum_threat": "Vulnerable to Shor's algorithm, enabling passive decryption of recorded traffic.",
    },
    "EC": {
        "family": "Elliptic Curve Cryptography",
        "description": "Generic Elliptic Curve key material.",
        "quantum_threat": "Vulnerable to Shor's algorithm.",
    },
    "DSA": {
        "family": "Digital Signature Algorithm",
        "description": "Discrete logarithm signature standard.",
        "quantum_threat": "Vulnerable to Shor's algorithm.",
    },
    "ED25519": {
        "family": "Edwards-curve Digital Signature",
        "description": "High-speed elliptic curve signature algorithm.",
        "quantum_threat": "Vulnerable to quantum discrete logarithm attacks.",
    },
    "ED448": {
        "family": "Edwards-curve Digital Signature",
        "description": "High-security elliptic curve signature algorithm.",
        "quantum_threat": "Vulnerable to quantum discrete logarithm attacks.",
    },
}

PQC_STANDARDIZED_ALGORITHMS = {
    "ML-KEM": {
        "family": "Post-Quantum Key Encapsulation Mechanism (NIST FIPS 203)",
        "description": "Lattice-based module lattice key-encapsulation mechanism.",
        "quantum_threat": "Resistant to known quantum and classical attacks.",
    },
    "ML-DSA": {
        "family": "Post-Quantum Digital Signature Standard (NIST FIPS 204)",
        "description": "Lattice-based digital signature algorithm.",
        "quantum_threat": "Resistant to known quantum and classical attacks.",
    },
    "SLH-DSA": {
        "family": "Stateless Hash-Based Digital Signature Standard (NIST FIPS 205)",
        "description": "Hash-based digital signature scheme.",
        "quantum_threat": "Resistant to quantum computer attacks based on hash function security.",
    },
}

SYMMETRIC_ALGORITHMS = {
    "AES-256-GCM": {
        "family": "Symmetric Authenticated Encryption (AEAD)",
        "description": "256-bit Advanced Encryption Standard in Galois/Counter Mode.",
        "quantum_threat": "Grover's algorithm reduces effective security from 256 bits to 128 bits, which remains secure.",
    },
    "AES-256": {
        "family": "Symmetric Encryption",
        "description": "256-bit Advanced Encryption Standard.",
        "quantum_threat": "Grover's algorithm reduces security to 128 bits; still quantum-resistant provided key schedule and mode are secure.",
    },
    "AES-128": {
        "family": "Symmetric Encryption",
        "description": "128-bit Advanced Encryption Standard.",
        "quantum_threat": "Grover's algorithm reduces effective search space to 64 bits. Migration to 256-bit keys recommended.",
    },
    "CHACHA20": {
        "family": "Symmetric Stream Cipher",
        "description": "256-bit stream cipher.",
        "quantum_threat": "256-bit key provides 128-bit quantum security against Grover's search.",
    },
}


def assess_single_algorithm(algorithm_raw: str, match_type: str = "parsed") -> Dict[str, Any]:
    algorithm = algorithm_raw.strip().upper()
    confidence = "HIGH" if match_type == "parsed" else "MEDIUM"
    manual_review_required = match_type != "parsed"

    if algorithm in QUANTUM_VULNERABLE_ALGORITHMS:
        info = QUANTUM_VULNERABLE_ALGORITHMS[algorithm]
        return {
            "algorithm": algorithm,
            "risk_level": "HIGH",
            "priority": "HIGH" if match_type == "parsed" else "MEDIUM",
            "confidence": confidence,
            "match_type": match_type,
            "category": info["family"],
            "reason": f"{info['description']} {info['quantum_threat']}",
            "recommendation": f"Plan migration to NIST post-quantum standards (e.g., ML-KEM for key exchange, ML-DSA or SLH-DSA for signatures).",
            "is_quantum_safe": False,
            "manual_review_required": manual_review_required,
        }

    if algorithm in PQC_STANDARDIZED_ALGORITHMS:
        info = PQC_STANDARDIZED_ALGORITHMS[algorithm]
        return {
            "algorithm": algorithm,
            "risk_level": "PQC",
            "priority": "LOW",
            "confidence": confidence,
            "match_type": match_type,
            "category": info["family"],
            "reason": f"{info['description']} {info['quantum_threat']}",
            "recommendation": "Verify implementation compliance with NIST FIPS standards and ensure secure key management.",
            "is_quantum_safe": True,
            "manual_review_required": manual_review_required,
        }

    if algorithm in SYMMETRIC_ALGORITHMS:
        info = SYMMETRIC_ALGORITHMS[algorithm]
        risk = "LOWER"
        priority = "LOW"
        if algorithm == "AES-128":
            recommendation = "Consider upgrading key size to AES-256 for long-term 128-bit quantum security under Grover's algorithm."
        else:
            recommendation = "Ensure unique nonces/IVs per encryption and secure key lifecycle management."

        return {
            "algorithm": algorithm,
            "risk_level": risk,
            "priority": priority,
            "confidence": confidence,
            "match_type": match_type,
            "category": info["family"],
            "reason": f"{info['description']} {info['quantum_threat']}",
            "recommendation": recommendation,
            "is_quantum_safe": True if algorithm != "AES-128" else False,
            "manual_review_required": manual_review_required,
        }

    return {
        "algorithm": algorithm,
        "risk_level": "UNKNOWN",
        "priority": "MEDIUM",
        "confidence": "LOW",
        "match_type": match_type,
        "category": "Unclassified Algorithm",
        "reason": "The algorithm was detected via pattern matching or metadata but could not be definitively evaluated against NIST PQC guidelines.",
        "recommendation": "Perform manual cryptographic audit of the codebase or asset configuration.",
        "is_quantum_safe": False,
        "manual_review_required": True,
    }


def analyze_asset_content(filename: str, content: bytes) -> Dict[str, Any]:
    """
    Analyzes asset file bytes. Handles PEM X.509 certificates and safe text file scanning.
    Distinguishes parsed cryptographic findings (high confidence) from text heuristic matches (medium/low confidence).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

    findings: List[Dict[str, Any]] = []
    asset_type = "Unknown"
    parsed_successfully = False
    details: Dict[str, Any] = {}
    detected_algos: List[str] = []

    # 1. Attempt PEM X.509 Certificate parsing
    try:
        cert = x509.load_pem_x509_certificate(content)
        parsed_successfully = True
        asset_type = "X.509 Certificate (PEM)"
        public_key = cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            detected_algos.append("RSA")
            details["key_size"] = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            detected_algos.append("ECDSA")
            details["curve"] = public_key.curve.name
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            detected_algos.append("ED25519")
        elif isinstance(public_key, ed448.Ed448PublicKey):
            detected_algos.append("ED448")
        else:
            detected_algos.append("EC")
            details["key_type"] = type(public_key).__name__

        try:
            if cert.signature_hash_algorithm:
                details["signature_hash"] = cert.signature_hash_algorithm.name
        except Exception:
            details["signature_hash"] = "Unknown"

        details["subject"] = cert.subject.rfc4514_string()
        details["issuer"] = cert.issuer.rfc4514_string()
        details["serial_number"] = str(cert.serial_number)

        for algo in detected_algos:
            findings.append(assess_single_algorithm(algo, match_type="parsed"))

    except Exception:
        # Fallback to text / configuration file heuristic scanning
        asset_type = "Text / Configuration File"
        text_content = content.decode("utf-8", errors="ignore").upper()

        candidates = [
            "ML-KEM",
            "ML-DSA",
            "SLH-DSA",
            "AES-256-GCM",
            "AES-256",
            "AES-128",
            "CHACHA20",
            "ECDSA",
            "ECDH",
            "ED25519",
            "ED448",
            "RSA",
            "DSA",
            "EC",
        ]

        for candidate in candidates:
            if candidate in text_content:
                detected_algos.append(candidate)
                findings.append(assess_single_algorithm(candidate, match_type="heuristic_text"))

    # If no algorithm detected
    if not findings:
        findings.append({
            "algorithm": "NONE_DETECTED",
            "risk_level": "UNKNOWN",
            "priority": "LOW",
            "confidence": "LOW",
            "match_type": "none",
            "category": "No Cryptographic Signatures Found",
            "reason": "No recognized classical or post-quantum cryptographic primitives were detected in this asset.",
            "recommendation": "Maintain asset inventory monitoring.",
            "is_quantum_safe": True,
            "manual_review_required": False,
        })

    # Overall risk determination
    risk_levels = [f["risk_level"] for f in findings]
    if "HIGH" in risk_levels:
        overall_risk = "HIGH"
        overall_priority = "HIGH"
        overall_rec = "Action required: Asset uses quantum-vulnerable cryptography (e.g., RSA/ECC). Plan migration."
    elif "PQC" in risk_levels:
        overall_risk = "PQC"
        overall_priority = "LOW"
        overall_rec = "Asset uses recognized post-quantum algorithms. Verify implementation compliance."
    elif "LOWER" in risk_levels:
        overall_risk = "LOWER"
        overall_priority = "LOW"
        overall_rec = "Asset uses symmetric cryptography. Ensure 256-bit key lengths and safe operation mode."
    else:
        overall_risk = "UNKNOWN"
        overall_priority = "MEDIUM"
        overall_rec = "Algorithm status unconfirmed. Perform cryptographic inspection."

    overall_confidence = "HIGH" if parsed_successfully else ("MEDIUM" if detected_algos else "LOW")
    manual_review_required = (not parsed_successfully) or any(f.get("manual_review_required") for f in findings)

    # Filename caveat check: ensure filename alone does not trick engine
    name_upper = filename.upper()
    filename_claims_pqc = any(pqc in name_upper for pqc in ["ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM"])
    if filename_claims_pqc and overall_risk == "HIGH":
        details["filename_warning"] = (
            "Filename suggests PQC usage, but actual parsed content contains quantum-vulnerable key material (e.g., RSA/ECC)."
        )

    if not parsed_successfully and detected_algos:
        details["evidence_notes"] = "Heuristic scan detected algorithm names in text content; confirm actual implementation before acting on migration decisions."

    evidence = [
        {
            "type": "parsed_certificate" if parsed_successfully else "heuristic_text",
            "source": "certificate_parse" if parsed_successfully else "text_scan",
            "algorithm": finding["algorithm"],
            "risk_level": finding["risk_level"],
            "confidence": finding["confidence"],
            "match_type": finding["match_type"],
            "manual_review_required": bool(finding.get("manual_review_required", False)),
        }
        for finding in findings
    ]

    return {
        "filename": filename,
        "asset_type": asset_type,
        "overall_risk_level": overall_risk,
        "overall_priority": overall_priority,
        "overall_confidence": overall_confidence,
        "overall_recommendation": overall_rec,
        "algorithms_detected": detected_algos,
        "findings": findings,
        "evidence": evidence,
        "details": details,
        "manual_review_required": manual_review_required,
        "disclaimer": (
            "Explainable Risk Engine v1.1. Parsed findings carry HIGH confidence, text heuristics carry MEDIUM confidence, and heuristically matched results should be manually validated before a migration decision."
        ),
    }
