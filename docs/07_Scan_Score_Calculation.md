# 7. Scan Score Calculation

## 7.1 Overview
The QuantumGuard TLS/SSL scan calculates a vulnerability score for every scanned domain. The score starts at a baseline of **100 points** (representing a perfectly secure, modern, quantum-ready configuration) and is reduced for every insecure, deprecated, or legacy protocol and cipher detected during the scan.

## 7.2 Score Reduction Table
The following table outlines exactly how the score is reduced and why these penalties occur:

| Vulnerability Detected | Point Reduction | Reason |
| :--- | :--- | :--- |
| **Missing TLS 1.3** | `-20` | TLS 1.3 is the modern standard for secure connections. Missing it means relying on older protocols that have larger attack surfaces. |
| **Weak Ciphers Detected (RC4/DES)** | `-20` | RC4 and DES are fundamentally broken and severely insecure. They can be decrypted by attackers in near real-time. |
| **RSA Key < 2048 bits** | `-20` | Weak RSA keys can be cracked using classical computing brute-force methods. |
| **TLS 1.0 Supported (Insecure)** | `-15` | TLS 1.0 is deprecated and highly vulnerable to downgrade attacks (like POODLE and BEAST). |
| **No Post-Quantum Key Exchange** | `-15` | Lacking a PQC exchange (like ML-KEM/Kyber) leaves data exposed to "Harvest Now, Decrypt Later" quantum attacks. |
| **TLS 1.1 Supported (Deprecated)** | `-10` | TLS 1.1 is obsolete and no longer considered secure by modern web standards. |
| **Classical RSA Key (>= 2048)** | `-5` | While 2048-bit RSA is currently classically secure, it is highly vulnerable to future quantum decryption (Shor's Algorithm). |

*Note: The lowest possible score is bounded at 0. Negative score calculations are capped at 0.*

## 7.3 Example Calculation
Let's walk through an example calculation for a legacy banking web server.

**Initial Score**: `100`

**Scan Findings:**
1. The server supports **TLS 1.0** for older browser compatibility: `-15` points.
2. The server supports **TLS 1.1**: `-10` points.
3. The server has **TLS 1.3** enabled: No penalty (`-0` points).
4. The server uses an older **RSA 1024-bit** certificate: `-20` points.
5. Because it is using legacy infrastructure, it does **not** have Post-Quantum Key Exchange (like Kyber): `-15` points.
6. The cipher suite allows **RC4**: `-20` points.

**Calculation:**
`100 (Base) - 15 (TLS 1.0) - 10 (TLS 1.1) - 20 (RSA < 2048) - 15 (No PQC) - 20 (RC4) = 20`

**Final Score:** **`20 / 100`**
This score corresponds to the **Legacy / Vulnerable** maturity tier, indicating immediate critical remediation is required.