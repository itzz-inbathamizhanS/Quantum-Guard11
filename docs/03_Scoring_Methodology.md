# 3. Scoring Methodology

## 3.1 Overview
The QuantumGuard Post-Quantum Cryptography (PQC) readiness score is derived using a multi-dimensional assessment model. It provides organizations with an objective measure of their vulnerability to "Harvest Now, Decrypt Later" (HNDL) attacks.

The scoring system operates at two distinct levels:
1. **TLS Quantum Score** (0–100): Server-side assessment of TLS configuration, cipher suites, key exchange, and PQC readiness.
2. **Maturity Assessment Score** (1.0–4.0, mapped to 0–100): Organizational assessment across four dimensions using questionnaire-based evaluation.

## 3.2 TLS Quantum Scoring (Server-Side)

### 3.2.1 Bounded Normalized Weighted Risk Model

The TLS quantum score uses a bounded, normalized formula that **mathematically guarantees** scores stay within [0, 100]:

```
Score = max(0, min(100, round(100 × (1 - TotalWeightedRisk / MaxTheoreticalRisk))))
```

Where:
- `TotalWeightedRisk = Σ(penalty_i)` for each category (capped at category maximum)
- `MaxTheoreticalRisk = 100` (sum of all category caps)

### 3.2.2 Category Weights (Shor > Grover Prioritization)

Categories are weighted based on quantum threat severity. **Shor's algorithm** (exponential speedup, breaks asymmetric crypto) is prioritized over **Grover's algorithm** (quadratic speedup, weakens symmetric crypto).

The backend now also emits a structured score breakdown so the user can see each category penalty, the theoretical maximum, and the normalized formula used to generate the final score.

| Category | Max Penalty | Quantum Threat | Rationale |
|---|---|---|---|
| **Key Exchange (KEM)** | 30 | Shor's (exponential) | RSA/ECDH key exchange is fully broken by Shor's. Highest priority for PQC migration. |
| **Signatures** | 20 | Shor's (exponential) | RSA/ECDSA signatures are fully broken by Shor's. |
| **Protocol Version** | 20 | Compliance/downgrade | TLS 1.0/1.1 enable downgrade attacks; TLS 1.3 required for CNSA 2.0. |
| **Symmetric Ciphers** | 15 | Grover's (quadratic) | Grover's halves effective key length. AES-256 → 128-bit security (still safe). |
| **Certificate Hygiene** | 10 | Operational | Key size, signature hash, classical operational risk. |
| **Vulnerability Posture** | 5 | Binary checks | Weak cipher presence (RC4, DES). |

**MaxTheoreticalRisk = 30 + 20 + 20 + 15 + 10 + 5 = 100**

### 3.2.3 Mathematical Proof of Bounds

```
Given:  0 ≤ penalty_i ≤ category_max_i  (for all categories i)
Then:   0 ≤ TotalWeightedRisk ≤ MaxTheoreticalRisk = 100
Thus:   0 ≤ TotalWeightedRisk / 100 ≤ 1
Thus:   0 ≤ (1 - ratio) ≤ 1
Thus:   0 ≤ 100 × (1 - ratio) ≤ 100
With:   max(0, min(100, ...)) as belt-and-suspenders clamp
∴       Score ∈ [0, 100]  for ALL possible inputs.  ∎
```

### 3.2.4 PQC Detection

The scanner recognizes the following post-quantum algorithms:
- **ML-KEM** (FIPS 203) — formerly CRYSTALS-Kyber
- **ML-DSA** (FIPS 204) — formerly CRYSTALS-Dilithium
- **SLH-DSA** (FIPS 205) — formerly SPHINCS+
- **Hybrid groups** — X25519MLKEM768, X25519Kyber768, secp256r1MLKEM768
- **Classic McEliece**

### 3.2.5 Recent Implementation Notes

**Before:** the system measured TLS quantum posture without an explicit per-category score breakdown in the UI, and the node-based TLS probe could mis-handle TLS version names when mapping to the runtime API.

**After:** the backend now returns a structured `score_breakdown` object with category penalties, normalized formula, and human-readable reasoning. The frontend now renders a subdomain comparison panel that highlights the strongest and weakest scanned subdomains and explains the gap using the top penalty categories.

**Why:** this improves transparency and makes it easier to answer questions like “why is this subdomain 40 while another is 60?” by exposing specific risk categories rather than only a single aggregate score.

**What changed:**
- Added structured score breakdowns for categories such as key exchange, signatures, protocol version, symmetric ciphers, certificate hygiene, and vulnerability posture.
- Added subdomain comparison UI support to compare highest/lowest scanned subdomains and identify the categories driving the score gap.
- Improved supported group inference and TLS probe version normalization in the scanner to prevent invalid runtime version names.

## 3.3 Maturity Assessment Scoring (Client-Side)

### 3.3.1 Evaluation Dimensions
The methodology evaluates the organization across four critical dimensions:
1. **CVI (Cryptographic Visibility & Inventory)**: The organization's capability to discover, inventory, and track cryptographic assets (keys, certificates, algorithms).
2. **SGRM (Strategic Governance & Risk Management)**: The presence of executive sponsorship, policies, and strategic roadmaps for PQC transition.
3. **DPE (Data Protection Engineering)**: The current implementation of encryption, focusing on agility and the isolation of sensitive data.
4. **ITR (Implementation & Technical Readiness)**: Technical mechanisms in place to deploy and operate quantum-safe algorithms.

### 3.3.2 Question-Level Scoring
Responses to each control are assigned a mathematical weight ranging from 1 to 4:
*   **1 Point (Non-Existent / Ad-Hoc)**: No formal process exists; completely vulnerable to quantum threats.
*   **2 Points (Developing)**: Initial discussions or partial visibility, but heavily reliant on manual processes.
*   **3 Points (Established)**: Formalized, documented policies and active cryptographic inventories exist.
*   **4 Points (Optimized / Quantum-Safe)**: Fully automated, agile cryptography utilizing NIST-approved PQC algorithms (e.g., ML-KEM, ML-DSA).

### 3.3.3 Dimension Score Aggregation
QuantumGuard computes the score for each Dimension using a **Weighted Harmonic Mean** of practice scores within that dimension. The harmonic mean penalizes low outliers more than arithmetic mean, reflecting the principle that cryptographic security is only as strong as its weakest element.

**Overall Score**: Computed using the **Weighted Geometric Mean** of dimension scores, mapped to a 0–100 scale for dashboard display:
```
Score100 = ((rawScore - 1.0) / 3.0) × 100
```

## 3.4 The Weakest Link Principle
Unlike traditional cybersecurity maturity models that rely heavily on pure averages, QuantumGuard employs the **Weakest Link Principle**. Cryptographic security is only as strong as its weakest element. An organization might have advanced governance (SGRM = 4.0), but if they lack visibility into their cryptographic assets (CVI = 1.0), they are highly susceptible to an HNDL attack.

## 3.5 Maturity Levels Mapping
The final score is mapped to a 5-level maturity tier to provide actionable insights for executives:

| Score Range | Maturity Tier | Profile Characteristics | HNDL Risk |
| :--- | :--- | :--- | :--- |
| **1.0 - 1.4** | **1 - Basic** | Ad-hoc cryptographic practices. Decentralized key management. | **CRITICAL** |
| **1.5 - 2.4** | **2 - Developing** | Initial awareness. Manual spreadsheets for inventory. No agility. | **HIGH** |
| **2.5 - 3.4** | **3 - Established** | Formalized inventory and risk tracking. Automated discovery tools deployed. | **MODERATE** |
| **3.5 - 3.9** | **4 - Advanced** | Cryptographic agility implemented in core systems. Hybrid (Classical/PQC) algorithms tested. | **LOW** |
| **4.0** | **5 - Optimizing** | Fully quantum-safe, agile, and automated cryptography. Native PQC algorithms in production. | **NEGLIGIBLE** |
