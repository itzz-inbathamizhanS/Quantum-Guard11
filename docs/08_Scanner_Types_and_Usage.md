# 8. Scanner Types & Usage

QuantumGuard features multiple distinct cryptographic scanners to provide a holistic view of your organization's post-quantum readiness.

## 8.1 TLS Post-Quantum Scanner
The core offering of QuantumGuard is the live TLS Scanner.
*   **What it does:** It actively connects to internet-facing web servers and performs cryptographic handshakes to determine protocol support, cipher suite preferences, and certificate algorithms.
*   **How it works:** It uses custom socket connections (bypassing native OS restrictions) to probe for specific protocols like TLS 1.0, 1.1, 1.2, and 1.3. It actively identifies if Post-Quantum Cryptography (PQC) key exchanges like **ML-KEM (Kyber)** are supported.
*   **Usage:** Enter any domain (e.g., `example.com`) in the Assessment or Tools panel and click "Scan".

## 8.2 Dependency Scanner (Coming Soon)
A planned feature to integrate directly into your CI/CD pipelines.
*   **What it does:** It analyzes your `package.json`, `requirements.txt`, or `go.mod` files to identify legacy cryptographic libraries (like old versions of OpenSSL or BouncyCastle).
*   **Usage:** Will be available as a CLI tool or GitHub Action.

## 8.3 Code / AST Scanner (Coming Soon)
A planned static analysis tool for codebases.
*   **What it does:** It parses the Abstract Syntax Tree (AST) of your source code to detect hardcoded keys, weak random number generators, or direct invocations of legacy algorithms like `MD5` or `SHA-1`.
*   **Usage:** Will be integrated into IDEs (VS Code) and pre-commit hooks.
