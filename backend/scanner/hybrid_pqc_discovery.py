"""
Hybrid PQC Deep Asset Discovery Module

This module implements specialized asset discovery targeting cryptographic infrastructure
using hybrid post-quantum cryptography mechanisms. It combines classical algorithms
(X25519, ECDSA, Ed25519) with PQC variants (ML-KEM-768/Kyber, ML-DSA/Dilithium, SLH-DSA)
as per industry adoption patterns from Cloudflare, Google ("X-Wing"), and enterprise PKI.

Discovery Targets:
- TLS/SSL infrastructure (web traffic, priority given to X25519MLKEM768 adoption)
- PKI/Certificate management (hybrid CA chains, EJBCA)
- VPN/IPsec/IKEv2 endpoints (secure infrastructure)
- IoT security gateways (long-term data protection)
- Enterprise identity & SSI wallets
- Financial sector high-value assets

Key Hybrid Combinations Targeted:
  KEM: X25519 + Kyber768/ML-KEM-768 (most deployed)
  KEX: X25519MLKEM768, SECP256R1MLKEM768, SECP384R1MLKEM1024
  Signatures: ML-DSA (Dilithium), SLH-DSA (SPHINCS+)
"""

from __future__ import annotations

import re
from typing import Iterable

# === Hybrid PQC Wordlist Tokens ===
# These tokens prioritize infrastructure with cryptographic specialization and quantum readiness

HYBRID_PQC_INFRASTRUCTURE_PREFIXES = [
    # === TLS/PKI Core (Highest Priority) ===
    "tls",  # TLS endpoint discovery
    "pki",  # Public Key Infrastructure
    "ca",  # Certificate Authority
    "crl",  # Certificate Revocation List
    "ocsp",  # OCSP responder
    "cert",  # Certificate services
    "root",  # Root CA endpoint
    "intermediate",  # Intermediate CA
    "signing",  # Code/document signing
    
    # === Cryptographic Services ===
    "crypto",  # Cryptographic services
    "kms",  # Key Management Service
    "hsm",  # Hardware Security Module
    "key",  # Key generation/storage
    "vault",  # Secrets management
    "secret",  # Secret management
    "cipher",  # Cipher configuration
    "encrypt",  # Encryption services
    "decrypt",  # Decryption services
    
    # === VPN & Secure Infrastructure ===
    "vpn",  # VPN gateways
    "ipsec",  # IPsec endpoints
    "ikev2",  # IKEv2 protocol endpoints
    "openvpn",  # OpenVPN servers
    "wireguard",  # WireGuard endpoints
    "tunnel",  # Tunneling protocol endpoints
    "gateway",  # Enterprise gateways
    
    # === Identity & Auth Services ===
    "idp",  # Identity Provider
    "sso",  # Single Sign-On
    "oauth",  # OAuth endpoints
    "oidc",  # OpenID Connect
    "mfa",  # Multi-factor auth
    "2fa",  # Two-factor auth
    "identity",  # Identity services
    "auth",  # Authentication
    "saml",  # SAML endpoints
    "kerberos",  # Kerberos services
    "ldap",  # LDAP services
    
    # === Enterprise Security ===
    "firewall",  # Firewall/UTM
    "waf",  # Web Application Firewall
    "proxy",  # Proxy services
    "balancer",  # Load balancer
    "edge",  # Edge security
    "perimeter",  # Perimeter security
    "dmz",  # DMZ services
    
    # === Financial Sector (High Value) ===
    "banking",  # Banking infrastructure
    "payments",  # Payment systems
    "settlement",  # Settlement services
    "clearing",  # Clearing services
    "swift",  # SWIFT protocol
    "transaction",  # Transaction services
    "compliance",  # Compliance services
    "audit",  # Audit services
    "treasury",  # Treasury systems
    
    # === Utilities & Critical Infrastructure ===
    "scada",  # SCADA systems
    "iot",  # IoT gateways
    "industrial",  # Industrial control
    "infrastructure",  # Infrastructure
    "utility",  # Utility services
    "critical",  # Critical infrastructure
    
    # === API & Microservices ===
    "api",  # API endpoints
    "apigw",  # API Gateway
    "service",  # Service endpoints
    "mesh",  # Service mesh
    
    # === Development/Staging (Crypto Testing) ===
    "staging",  # Staging environments
    "test",  # Test environments
    "dev",  # Development environments
    "qa",  # QA environments
    "lab",  # Lab environments
]

# High-value combined tokens for PQC infrastructure
HYBRID_PQC_COMBINED_TOKENS = [
    "tlsca",
    "pkitls",
    "caauth",
    "cryptokms",
    "hsmsigning",
    "vaultcert",
    "vpnca",
    "idpauth",
    "ssokms",
    "bankingpki",
    "paymentskms",
    "infrasecurity",
]

# Common post-quantum algorithm name patterns
PQC_ALGORITHM_MARKERS = [
    "kyber",
    "mlkem",
    "ml-kem",
    "dilithium",
    "mldsa",
    "ml-dsa",
    "sphincs",
    "slhdsa",
    "slh-dsa",
    "pqc",
    "quantum",
    "postquantum",
]

# Classical-PQC hybrid markers  
HYBRID_KEX_MARKERS = [
    "x25519mlkem",
    "x25519kyber",
    "secp256r1mlkem",
    "secp256r1kyber",
    "secp384r1mlkem",
    "secp384r1kyber",
    "hybrid",
    "xwing",  # Google's X-Wing hybrid mechanism
]

# Cloudflare adoption pattern (X25519MLKEM768 leader)
CLOUDFLARE_HYBRID_TOKENS = [
    "cloudflare",
    "cf",
    "cfdns",
    "cfcdn",
    "cfkex",
]

# Industry vertical tokens (high PQC adoption)
INDUSTRY_VERTICAL_TOKENS = [
    "bank",  # Finance (~33% gas/water/utilities, ~25% personal goods)
    "finance",  # Financial services
    "government",  # Government
    "defense",  # Defense sector
    "healthcare",  # Healthcare
    "energy",  # Energy sector
    "transport",  # Transportation
    "retail",  # Retail
]


def _normalize_label(value: str) -> str:
    """Normalize token to lowercase alphanumeric."""
    return re.sub(r"[^a-z0-9-]", "", str(value or "").strip().lower())


def get_hybrid_pqc_wordlist() -> list[str]:
    """
    Return combined wordlist optimized for hybrid PQC infrastructure discovery.
    
    Combines:
    - Direct hybrid PQC infrastructure tokens
    - Combined high-value patterns
    - Algorithm-specific tokens
    - KEX hybrid markers
    - Industry vertical tokens
    """
    tokens: list[str] = []
    seen: set[str] = set()
    
    # Priority 1: Direct infrastructure
    for token in HYBRID_PQC_INFRASTRUCTURE_PREFIXES:
        normalized = _normalize_label(token)
        if normalized and normalized not in seen:
            seen.add(normalized)
            tokens.append(normalized)
    
    # Priority 2: Combined high-value patterns
    for token in HYBRID_PQC_COMBINED_TOKENS:
        normalized = _normalize_label(token)
        if normalized and normalized not in seen:
            seen.add(normalized)
            tokens.append(normalized)
    
    # Priority 3: Algorithm markers
    for token in PQC_ALGORITHM_MARKERS:
        normalized = _normalize_label(token)
        if normalized and normalized not in seen:
            seen.add(normalized)
            tokens.append(normalized)
    
    # Priority 4: Hybrid KEX patterns
    for token in HYBRID_KEX_MARKERS:
        normalized = _normalize_label(token)
        if normalized and normalized not in seen:
            seen.add(normalized)
            tokens.append(normalized)
    
    # Priority 5: Industry verticals
    for token in INDUSTRY_VERTICAL_TOKENS:
        normalized = _normalize_label(token)
        if normalized and normalized not in seen:
            seen.add(normalized)
            tokens.append(normalized)
    
    # Priority 6: Cloudflare adoption (X25519MLKEM768 leader)
    for token in CLOUDFLARE_HYBRID_TOKENS:
        normalized = _normalize_label(token)
        if normalized and normalized not in seen:
            seen.add(normalized)
            tokens.append(normalized)
    
    return tokens


def get_pqc_infrastructure_priority_map() -> dict[str, int]:
    """
    Return a priority map for PQC infrastructure discovery.
    
    Lower = higher priority for asset discovery.
    """
    priority_map: dict[str, int] = {}
    
    # Tier 1 (Priority 0-10): Critical TLS/PKI infrastructure
    tier1 = [
        "tls", "pki", "ca", "crl", "ocsp", "cert", "signing", "root",
        "x25519mlkem", "x25519kyber", "xwing", "kyber", "mlkem"
    ]
    for token in tier1:
        priority_map[_normalize_label(token)] = 0
    
    # Tier 2 (Priority 20-30): Cryptographic services & key management
    tier2 = [
        "kms", "hsm", "vault", "secret", "crypto", "encrypt",
        "dilithium", "mldsa", "sphinx", "slhdsa"
    ]
    for token in tier2:
        priority_map[_normalize_label(token)] = 20
    
    # Tier 3 (Priority 40-50): VPN & Infrastructure security
    tier3 = ["vpn", "ipsec", "ikev2", "gateway", "vpngw"]
    for token in tier3:
        priority_map[_normalize_label(token)] = 40
    
    # Tier 4 (Priority 60-70): Identity & authentication
    tier4 = ["idp", "sso", "oauth", "auth", "identity", "mfa"]
    for token in tier4:
        priority_map[_normalize_label(token)] = 60
    
    # Tier 5 (Priority 80-90): Financial/critical infrastructure
    tier5 = ["banking", "payments", "finance", "treasury", "clearing"]
    for token in tier5:
        priority_map[_normalize_label(token)] = 80
    
    return priority_map


def rank_pqc_tokens(tokens: Iterable[str]) -> list[str]:
    """
    Rank tokens by PQC infrastructure priority.
    
    Applies custom priority scoring for crypto infrastructure discovery.
    """
    priority_map = get_pqc_infrastructure_priority_map()
    
    scored: list[tuple[int, str]] = []
    seen: set[str] = set()
    
    for token in tokens:
        normalized = _normalize_label(token)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        
        # Score: lower is higher priority
        score = priority_map.get(normalized, 100)
        scored.append((score, normalized))
    
    # Sort by priority (ascending), then alphabetically for stability
    scored.sort(key=lambda x: (x[0], x[1]))
    return [token for _, token in scored]


def expand_pqc_tokens(base_tokens: Iterable[str]) -> list[str]:
    """
    Expand base tokens with PQC-aware transformations and combinations.
    
    Generates derived candidates targeting hybrid PQC patterns:
    - Token + crypto/kms/vault/pki suffixes
    - Common prefix + pqc/quantum/hybrid suffixes
    - Combined infrastructure patterns
    """
    base = list(base_tokens or [])
    expanded: list[str] = []
    seen: set[str] = set()
    
    def add_token(token: str) -> None:
        normalized = _normalize_label(token)
        if normalized and normalized not in seen:
            seen.add(normalized)
            expanded.append(normalized)
    
    # Add base tokens first
    for token in base:
        add_token(token)
    
    # PQC-aware suffixes for existing tokens
    pqc_suffixes = [
        "pqc", "quantum", "hybrid", "mlkem", "kyber", "dilithium",
        "kms", "vault", "crypto", "pki", "ca", "cert"
    ]
    
    for token in base:
        normalized = _normalize_label(token)
        if not normalized or len(normalized) > 20:
            continue
        
        for suffix in pqc_suffixes:
            combined = f"{normalized}{suffix}"
            if len(combined) <= 63:
                add_token(combined)
            
            # Reverse order for some patterns
            combined_rev = f"{suffix}{normalized}"
            if len(combined_rev) <= 63:
                add_token(combined_rev)
    
    # Add hybrid PQC wordlist
    for token in get_hybrid_pqc_wordlist():
        add_token(token)
    
    # Industry-specific hybrid patterns
    industry_patterns = {
        "bank": ["bankingpki", "bankca", "banktls", "paymentskms"],
        "finance": ["financepki", "financeauth", "treasurypki"],
        "government": ["govca", "govpki", "govauth"],
        "defense": ["defensepki", "securitykms"],
    }
    
    for base_tok in base:
        normalized = _normalize_label(base_tok)
        if normalized in industry_patterns:
            for pattern in industry_patterns[normalized]:
                add_token(pattern)
    
    return expanded[:500]  # Limit to prevent explosion


def detect_hybrid_pqc_markers(text: str) -> dict[str, list[str]]:
    """
    Scan text for hybrid PQC markers and return categorized findings.
    
    Returns dict with keys:
    - 'kex_hybrids': X25519MLKEM768, etc.
    - 'pqc_algorithms': Kyber, Dilithium, etc.
    - 'classical_algorithms': X25519, ECDSA, etc.
    - 'hybrid_patterns': Combined markers
    """
    content = str(text or "").upper()
    findings: dict[str, list[str]] = {
        "kex_hybrids": [],
        "pqc_algorithms": [],
        "classical_algorithms": [],
        "hybrid_patterns": [],
    }
    
    # KEX hybrid detection
    kex_patterns = [
        r"X25519MLKEM768",
        r"X25519[_-]?MLKEM[_-]?768",
        r"X25519KYBER768",
        r"SECP256R1MLKEM768",
        r"SECP384R1MLKEM1024",
        r"SECP256R1KYBER768",
        r"X[_-]?WING",
    ]
    for pattern in kex_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        findings["kex_hybrids"].extend(matches)
    
    # PQC algorithm detection
    pqc_patterns = [
        r"(?:ML[_-]?)?KEM(?:[_-]?768|[_-]?1024)?",
        r"KYBER(?:[_-]?768|[_-]?1024)?",
        r"ML[_-]?DSA",
        r"DILITHIUM",
        r"SLH[_-]?DSA",
        r"SPHINCS",
    ]
    for pattern in pqc_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        findings["pqc_algorithms"].extend(matches)
    
    # Classical algorithm detection
    classical_patterns = [
        r"X25519",
        r"X448",
        r"SECP(?:256R1|384R1|521R1)",
        r"(?:ED25519|ED448)",
        r"ECDSA",
        r"(?:RSA|RSA[_-]?PSS)",
    ]
    for pattern in classical_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        findings["classical_algorithms"].extend(matches)
    
    # Hybrid pattern detection (presence of both classical + PQC)
    if findings["classical_algorithms"] and findings["pqc_algorithms"]:
        findings["hybrid_patterns"].append("hybrid_detected")
        if findings["kex_hybrids"]:
            findings["hybrid_patterns"].append("hybrid_kex_explicit")
    
    return {k: list(set(v)) for k, v in findings.items()}


def score_host_for_hybrid_pqc(hostname: str, hybrid_pqc_markers: dict[str, list[str]] | None = None) -> tuple[float, str]:
    """
    Score a hostname for likelihood of hybrid PQC implementation.
    
    Returns (score, reason) where score 0-100 indicates PQC adoption likelihood.
    Higher score = more likely to use hybrid PQC.
    """
    host_lower = str(hostname or "").lower()
    score = 0.0
    reasons: list[str] = []
    
    # Score components
    if not host_lower:
        return 0.0, "empty_hostname"
    
    # 1. Hostname pattern matching
    pqc_keywords = [
        ("hybrid", 15), ("pqc", 15), ("quantum", 12),
        ("kms", 10), ("vault", 10), ("crypto", 8),
        ("tls", 8), ("pki", 18), ("ca", 14),
        ("kyber", 20), ("mlkem", 20), ("dilithium", 18),
        ("sphincs", 18), ("mldsa", 18),
    ]
    
    for keyword, points in pqc_keywords:
        if keyword in host_lower:
            score += points
            reasons.append(f"keyword_{keyword}")
    
    # 2. Infrastructure priority
    priority_keywords = [
        ("banking", 12), ("payment", 12), ("finance", 10),
        ("vpn", 8), ("gateway", 6), ("auth", 6),
        ("idp", 8), ("sso", 6),
    ]
    
    for keyword, points in priority_keywords:
        if keyword in host_lower:
            score += points
            reasons.append(f"sector_{keyword}")
    
    # 3. Add bonus for explicit hybrid markers if provided
    if hybrid_pqc_markers:
        if hybrid_pqc_markers.get("kex_hybrids"):
            score += 25
            reasons.append("explicit_kex_hybrid")
        if hybrid_pqc_markers.get("pqc_algorithms"):
            score += 20
            reasons.append("explicit_pqc_algo")
        if hybrid_pqc_markers.get("hybrid_patterns"):
            score += 15
            reasons.append("hybrid_pattern_detected")
    
    # Cap at 100
    final_score = min(100.0, score)
    reason = ", ".join(reasons) if reasons else "no_markers"
    
    return final_score, reason
