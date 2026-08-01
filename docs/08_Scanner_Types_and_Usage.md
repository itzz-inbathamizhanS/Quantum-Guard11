# 8. Scanner Types and Usage

## 8.1 Overview
QuantumGuard provides a suite of scanners to comprehensively assess your organization's post-quantum cryptography (PQC) readiness. These tools can be accessed through the **Tools** portal.

## 8.2 Available Scanners

### 8.2.1 Real-Time TLS/SSL Scanner
*   **What it uses**: Node.js built-in `tls` module.
*   **How it works**: Connects directly to the target domain over port 443 to perform deep protocol probing. It systematically attempts connections using TLS 1.0, 1.1, 1.2, and 1.3, capturing the precise cipher suites and certificates negotiated.
*   **Primary Use Case**: Checking external-facing web servers for legacy vulnerabilities and verifying if modern Post-Quantum Cryptography (PQC) key exchanges like ML-KEM/Kyber are enabled.

### 8.2.2 Dependency Scanner (Coming Soon)
*   **What it uses**: Static code analysis.
*   **How it works**: Parses `package.json`, `pom.xml`, and `requirements.txt` to cross-reference dependencies against known vulnerable or non-quantum-safe cryptographic libraries.
*   **Primary Use Case**: Identifying outdated cryptographic libraries deep within application codebases.

### 8.2.3 Source Code Analysis (Coming Soon)
*   **What it uses**: Pattern matching and AST parsing.
*   **How it works**: Scans source code for hardcoded encryption keys, explicit usage of deprecated algorithms (like MD5, SHA-1, RSA-1024), and poor entropy generation.
*   **Primary Use Case**: Securing the software supply chain and ensuring developers are using modern cryptographic APIs.

## 8.3 Running a Scan
To initiate a scan:
1. Navigate to the **Tools** page.
2. Enter the target hostname (e.g., `api.example.com`).
3. Select "Deep Scan" to probe individual legacy ciphers.
4. Click **Run Scan**. The results will populate the AI Chat Advisor context and generate a downloadable PDF report.