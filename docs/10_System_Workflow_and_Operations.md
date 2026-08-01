# 10. System Workflow & Operations

## 10.1 What We Scan and Why We Scan It
QuantumGuard actively scans internet-facing domains to evaluate their cryptographic posture.
*   **What it scans**: We scan the Transport Layer Security (TLS) configuration of web servers. This includes supported protocol versions (TLS 1.0 to 1.3), cipher suites (e.g., AES, ChaCha20, RC4), and X.509 Digital Certificates (Key sizes, Signature Algorithms).
*   **Why it scans**: Cryptography is transitioning due to the threat of Quantum Computers (the "Harvest Now, Decrypt Later" threat). We scan to ensure organizations are deprecating legacy, classically-vulnerable cryptography (like RSA-1024 and RC4) and adopting Post-Quantum Cryptography (PQC) key exchanges like ML-KEM (Kyber).

## 10.2 How Safety is Determined
Safety is not a simple "Yes/No", but rather a maturity spectrum derived from the **Q-Score (Quantum Score)**.
1.  The scanner evaluates the raw data from the TLS handshake.
2.  Penalties are applied for legacy components (e.g., `-20` for RC4, `-15` for lacking PQC).
3.  The final score (0-100) dictates the **Maturity Level**:
    *   **Level 1 (0 - 40)**: Unsafe / Legacy. Immediate action required.
    *   **Level 2 (40 - 60)**: Developing. Vulnerable to near-term threats.
    *   **Level 3 (60 - 80)**: Established. Classically secure, but lacks quantum agility.
    *   **Level 4 (80 - 99)**: Advanced. Highly secure with modern protocols.
    *   **Level 5 (100)**: Quantum-Ready. Perfectly safe and utilizing PQC algorithms.

## 10.3 The AI Security Advisor Model
To help developers understand their scan results, QuantumGuard integrates an AI Security Advisor.
*   **Which Model is Used**: We utilize Google's **Gemini 1.5 Flash** model via the official `@google/genai` SDK. 
*   **How it Works**: The complete JSON results of the TLS scan are injected directly into the Gemini model's context window. The model uses a highly strict `SYSTEM_PROMPT` to ensure it acts as a Senior Security Engineer, providing accurate, contextual remediation advice (like Nginx/Apache config snippets) based *only* on the scan data.

## 10.4 PDF Report Generation
Instead of relying on heavy backend PDF libraries, QuantumGuard generates sleek, stylized PDF reports entirely on the client side.
*   **The Library**: We use `html2pdf.js`, a client-side library that converts HTML DOM elements into a Canvas, and then outputs a PDF using `jsPDF`.
*   **The Workflow**: 
    1. The user clicks "Download Report".
    2. The application temporarily renders a hidden, highly-styled HTML template populated with the scan data (Scores, Vulnerabilities, Ciphers).
    3. `html2pdf.js` captures this DOM element, preserves all CSS styling and layout, and triggers a file download directly in the user's browser.

## 10.5 Environment and System Architecture
QuantumGuard operates on a lightweight, efficient backend.
*   **The Environment**: It runs on a **Node.js / Express.js** server. 
*   **Subdomain Discovery**: It uses the native Node `dns` module to resolve IP addresses and iterate through common subdomain prefixes (`www`, `api`, `mail`, etc.) to map out an organization's attack surface.
*   **Environment Variables**: The system securely loads the `GEMINI_API_KEY` via a `.env` file using the `dotenv` library to authorize requests to Google's AI Studio.

## 10.6 Leaderboard Generation and Syncing
The Leaderboard provides a competitive, gamified view of global PQC readiness.
*   **How it works**: Whenever a user scans a domain, the `score`, `hostname`, and `timestamp` are transmitted to the backend via `POST /api/subdomains` or the direct scanning route.
*   **Storage**: The backend maintains an in-memory array of the top scores, which is continuously persisted to a local `metadata.json` file to survive server reboots.
*   **Rendering**: The frontend (`leaderboard.html`) uses a JavaScript `fetch()` interval to query `/api/leaderboard` every 10 seconds. It sorts the array from highest to lowest score and dynamically manipulates the DOM to render the ranking tables, ensuring all users see real-time updates.
