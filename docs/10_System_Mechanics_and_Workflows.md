# 10. System Mechanics & Workflows

This document outlines the internal architecture, logic flows, and environmental setup of the QuantumGuard system.

## 10.1 Environment and Runtime

QuantumGuard is built as a highly performant **Node.js** web application using **Express.js**.

- **Backend Runtime**: Node.js (ES Modules).
- **Environment Configuration**: The system relies on a `.env` file at the root of the project to securely load sensitive credentials (such as the `GEMINI_API_KEY`).
- **Startup**: The application is started via `node src/server.js` (or `npm start`), binding to port 3000 by default and exposing both REST API endpoints and static frontend assets (HTML, CSS, JS).

## 10.2 The Scanning Engine (How it works)

When a user initiates a scan (e.g., on the Assessment or Tools page), the following workflow executes:

1. **Request Reception**: The frontend sends a POST request to initiate the TLS scan for a given hostname.
2. **Deep Probing (`src/scanner.js`)**: The backend utilizes the native Node.js `tls` socket module. It actively forces raw TCP connections on port 443 (HTTPS) to the target domain.
3. **Safety Determination**: 
   - The scanner explicitly requests legacy protocol handshakes (`TLSv1.0`, `TLSv1.1`, etc.). If the target server successfully completes a handshake using these deprecated protocols, it is flagged as **unsafe**.
   - It iterates over a strict list of known vulnerable legacy ciphers (e.g., RC4, DES, 3DES). If the server accepts any of them, it is marked as critically vulnerable.
   - It parses the negotiated X.509 certificate to check for weak RSA key sizes (<2048) and deprecated signature algorithms (SHA-1).
4. **Result Generation**: The collected cipher suites, protocols, and certificate metadata are serialized into a JSON object and assigned a "Quantum Score" based on the detected vulnerabilities.

## 10.3 AI Security Advisor (Gemini Integration)

QuantumGuard features an interactive AI assistant designed to interpret scan results and provide step-by-step remediation.

- **The Model**: The backend utilizes the official `@google/genai` SDK, specifically calling the lightning-fast **`gemini-1.5-flash`** model.
- **How it works**:
  1. The frontend collects the raw JSON output of a completed TLS scan alongside the user's chat message.
  2. This data is sent to the backend `/api/chat` endpoint.
  3. The backend validates the `GEMINI_API_KEY` from the environment file.
  4. It constructs a highly detailed context payload (injecting the scan JSON) and applies a strict `SYSTEM_PROMPT` instructing the AI to act as an accurate, empathetic Senior Security Engineer.
  5. The model streams its response back to the frontend chunk-by-chunk in real-time, parsing Markdown on the fly into the UI chat panel.

## 10.4 PDF Report Generation

Users can download full, comprehensive assessment reports directly from their browsers.

- **How it works**: PDF generation is entirely client-side. The frontend utility (`ui-utils.js`) intercepts the "Export PDF" command. It dynamically applies a print-optimized CSS layout, temporarily overriding the `document.title` to format the filename, and invokes the native browser `window.print()` dialog. The browser's built-in PDF generator handles the rendering, ensuring maximum privacy since the sensitive report data never leaves the user's local machine or is sent to a third-party server.

## 10.5 Global Leaderboard Mechanics

The Leaderboard provides a competitive ranking of all scanned domains based on their Post-Quantum readiness.

- **Data Storage**: When a scan completes on the backend, `src/leaderboard.js` intercepts the final JSON result. It extracts the target domain, final score, IP address, and timestamp into an in-memory cache. To prevent system crashes during bulk scanning, it intelligently "debounces" these updates and safely writes them asynchronously to a local `database.json` file.
- **Retrieval & Rendering**: The frontend `leaderboard.html` page polls the `/api/leaderboard` endpoint every 10 seconds. The backend serves the contents of `database.json`, and the frontend dynamically sorts the table from highest score (100) to lowest score (0), automatically updating the visual UI ranks in real-time.