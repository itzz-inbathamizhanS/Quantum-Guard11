# 9. TLS Scanner Deep Dive

## 9.1 Data Collection Methodology
The TLS Scanner is completely custom-built using the low-level Node.js `tls` socket module. It does not rely on third-party APIs (like Qualys SSLLabs). 

**How it gathers data:**
1. **Protocol Probing**: It iteratively opens TCP sockets and performs TLS handshakes, forcing specific protocol versions (`TLSv1.0`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`).
2. **Cipher Enumeration**: During TLS 1.2 probing, it iterates through a vast array of historical and modern cipher suites (including RC4, DES, AES, ChaCha20) to see which the server accepts.
3. **Certificate Extraction**: It intercepts the server's X.509 certificate during the handshake, parsing the Subject, Issuer, Key Type (RSA/ECDSA), Key Size, and Signature Algorithm.

## 9.2 Q-Score (Quantum Score) Calculation
Every scan begins with a perfect **Quantum Score of 100**. Points are explicitly deducted for every legacy configuration or non-quantum-safe parameter detected.

### 9.2.1 Score Penalty Table
The following table outlines exactly how the score is reduced based on protocol, cipher, and certificate analysis:

| Vulnerability Detected | Point Reduction | Reason |
| :--- | :--- | :--- |
| **Missing TLS 1.3** | `-20` | TLS 1.3 enforces modern, secure handshakes. Lacking it significantly degrades posture. |
| **Weak Ciphers Detected (RC4/DES)** | `-20` | RC4 and DES stream/block ciphers are fundamentally broken and allow real-time decryption. |
| **RSA Key < 2048 bits** | `-20` | Weak RSA keys can be cracked using classical computing brute-force methods. |
| **Supports TLS 1.0** | `-15` | TLS 1.0 is deprecated, vulnerable to POODLE/BEAST, and breaks modern compliance. |
| **No PQC Key Exchange** | `-15` | If the key exchange does not include quantum-resistant algorithms (Kyber, McEliece, Sphincs), the connection is vulnerable to "Harvest Now, Decrypt Later". |
| **Supports TLS 1.1** | `-10` | TLS 1.1 is obsolete and no longer recommended by NIST or Mozilla. |
| **RSA Key (>= 2048 bits)** | `-5` | Classically secure, but mathematically vulnerable to Shor's algorithm on a quantum computer. |

*Note: The total score cannot drop below 0. The final Quantum Score directly maps to the organization's Global Leaderboard ranking and maturity tier.*

## 9.3 Exact Reduction Example
Let's walk through an exact calculation for a legacy banking web server.

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