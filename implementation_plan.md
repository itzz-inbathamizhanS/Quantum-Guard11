# PDF Report Generation Plan

This plan details the transition from JSON downloads to PDF reports for the TLS scanner. The PDFs will be cleanly formatted to show exactly what cryptographic primitives a site is actively using, along with a transparent breakdown of how the quantum score was calculated.

## Proposed Changes

### 1. PDF Generation Logic in Frontend
- We will leverage the `html2pdf.js` library (already included in `tools.html`).
- A new hidden `div` container will be temporarily created in the DOM whenever a download is requested. We will populate this `div` with beautifully formatted HTML specifically tailored for printing, and then pass it to `html2pdf()`.

### 2. Report Content Requirements
The PDF will avoid listing unsupported/disabled features. It will only include:
- **Active Protocol Support**: Only TLS versions that returned `supported: true`.
- **Negotiated Cipher Suites**: The specific cipher suites that the server accepted.
- **Certificate Info**: Key type, size, signature algorithm, and validity period.
- **Score Calculation Breakdown**: A step-by-step math breakdown explaining the score. Since the backend `scanner.js` starts at 100, we will recreate the penalty logic in the PDF view:
  - Base Score: **100**
  - If TLS 1.3 is missing: **-20**
  - If TLS 1.0 is supported: **-15**
  - If TLS 1.1 is supported: **-10**
  - If RSA key < 2048: **-20**
  - If RSA key >= 2048: **-5**
  - If no Post-Quantum Cryptography (PQC) Key Exchange is found: **-15**
  - If RC4 or DES weak ciphers are found: **-20**

### 3. Modifying Download Buttons
- Update the **Download Main Report** button to trigger the single-domain PDF generation.
- Update the **Download Individual Subdomain** button to trigger a single-domain PDF generation for that specific subdomain.
- Update the **Download All Reports** button to concatenate the HTML for the main domain and all active subdomains (separated by page breaks `page-break-before: always;`) into one large, multi-page PDF.

## User Review Required
> [!IMPORTANT]
> Since PDF generation runs purely client-side, the "Download All" feature for a large number of subdomains might take a few seconds to process in the browser. A loading indicator will be shown on the cursor while the PDF is generating.

Please review this plan and click **Proceed** if you approve of this approach to generating the PDF reports!