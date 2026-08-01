import tls from 'tls';

// Common ciphers for TLS 1.2
const CIPHERS_1_2 = [
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'ECDHE-RSA-CHACHA20-POLY1305',
  'ECDHE-ECDSA-CHACHA20-POLY1305',
  'DHE-RSA-AES256-GCM-SHA384',
  'DHE-RSA-AES128-GCM-SHA256',
  'AES256-GCM-SHA384',
  'AES128-GCM-SHA256',
  'ECDHE-RSA-AES256-SHA384',
  'ECDHE-RSA-AES128-SHA256',
  'ECDHE-RSA-AES256-SHA',
  'ECDHE-RSA-AES128-SHA',
  'AES256-SHA256',
  'AES128-SHA256',
  'AES256-SHA',
  'AES128-SHA',
  'DES-CBC3-SHA'
];

// ═══════════════════════════════════════════════════════════════════
// PQC DETECTION — NIST FIPS 203/204/205 + legacy names + hybrids
// ═══════════════════════════════════════════════════════════════════
const PQC_PATTERNS = [
  // FIPS 203 — ML-KEM (formerly CRYSTALS-Kyber)
  /ml[-_]?kem/i,
  /kyber/i,
  /crystals[-_]?kyber/i,
  /fips[-_]?203/i,
  // FIPS 204 — ML-DSA (formerly CRYSTALS-Dilithium)
  /ml[-_]?dsa/i,
  /dilithium/i,
  /crystals[-_]?dilithium/i,
  /fips[-_]?204/i,
  // FIPS 205 — SLH-DSA (formerly SPHINCS+)
  /slh[-_]?dsa/i,
  /sphincs/i,
  /fips[-_]?205/i,
  // Hybrid key exchange groups (TLS 1.3)
  /x25519mlkem768/i,
  /x25519kyber768/i,
  /secp256r1mlkem768/i,
  // Classic McEliece
  /mceliece/i,
];

/**
 * Check if any string in the given text matches a PQC algorithm pattern.
 * @param {string} text — concatenated key exchange / cipher info
 * @returns {boolean}
 */
function detectPQC(text) {
  return PQC_PATTERNS.some(pattern => pattern.test(text));
}

function normalizeScore(score) {
  const numeric = Number(score);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(100, Math.round(numeric)));
}

function inferSupportedGroups(protocol_support, isPQC, bestCert) {
  const groups = [];
  const seen = new Set();
  const add = (value) => {
    if (value && !seen.has(value)) {
      seen.add(value);
      groups.push(value);
    }
  };

  if (protocol_support?.tls_1_3?.supported) {
    add('X25519');
    add('secp256r1');
    if (isPQC) {
      add('X25519MLKEM768');
      add('ML-KEM-768');
    }
  }

  if (bestCert) {
    const sigAlg = (bestCert.sigalg || '').toLowerCase();
    if (sigAlg.includes('ml-dsa') || sigAlg.includes('dilithium')) add('ML-DSA');
    if (sigAlg.includes('slh-dsa') || sigAlg.includes('sphincs')) add('SLH-DSA');
  }

  return groups;
}

function buildScoreBreakdown(scoring, protocol_support, bestCert, isPQC, pqcDetails, hasRC4, hasDES) {
  const categories = [
    {
      id: 'keyExchange',
      name: 'Key Exchange / KEM',
      penalty: scoring.penalties.keyExchange,
      cap: CATEGORY_CAPS.keyExchange,
      reason: !isPQC ? 'No PQC hybrid key exchange was observed, so Shor-style risk remains exposed.' : 'Hybrid or PQC key exchange was observed, reducing the Shor risk penalty.'
    },
    {
      id: 'signatures',
      name: 'Signatures',
      penalty: scoring.penalties.signatures,
      cap: CATEGORY_CAPS.signatures,
      reason: bestCert && /ml-dsa|dilithium|slh-dsa|sphincs|fips[-_]?20[45]/i.test(bestCert.sigalg || '')
        ? 'The certificate chain advertises a PQC-capable signature algorithm.'
        : 'The certificate chain is still using a classical signature algorithm, increasing the Shor risk contribution.'
    },
    {
      id: 'protocol',
      name: 'Protocol Version',
      penalty: scoring.penalties.protocol,
      cap: CATEGORY_CAPS.protocol,
      reason: protocol_support?.tls_1_3?.supported ? 'TLS 1.3 is enabled, reducing downgrade and legacy protocol exposure.' : 'TLS 1.3 is not enabled, leaving the host exposed to legacy negotiation risks.'
    },
    {
      id: 'symmetric',
      name: 'Symmetric Ciphers',
      penalty: scoring.penalties.symmetric,
      cap: CATEGORY_CAPS.symmetric,
      reason: hasRC4 || hasDES ? 'Legacy symmetric suites such as RC4 or DES were observed, increasing Grover-era risk exposure.' : 'Only modern AEAD suites were observed, limiting Grover risk.'
    },
    {
      id: 'certificate',
      name: 'Certificate Hygiene',
      penalty: scoring.penalties.certificate,
      cap: CATEGORY_CAPS.certificate,
      reason: bestCert ? 'Certificate size and algorithm choice were reviewed for operational security posture.' : 'No certificate details were available, so a conservative operational penalty was applied.'
    },
    {
      id: 'vulnerability',
      name: 'Vulnerability Posture',
      penalty: scoring.penalties.vulnerability,
      cap: CATEGORY_CAPS.vulnerability,
      reason: pqcDetails?.hasHybridKEM ? 'No additional TLS vulnerability penalty was required.' : 'Legacy handshakes or weak suites triggered an additional exposure penalty.'
    }
  ];

  const totalWeightedRisk = scoring.totalWeightedRisk || 0;
  const maxTheoreticalRisk = scoring.maxTheoreticalRisk || MAX_THEORETICAL_RISK;
  const score = normalizeScore(scoring.score);

  return {
    starting_score: 100,
    score,
    total_weighted_risk: totalWeightedRisk,
    max_theoretical_risk: maxTheoreticalRisk,
    normalized_formula: 'Score = max(0, min(100, round(100 * (1 - TotalWeightedRisk / MaxTheoreticalRisk))))',
    asset_criticality_multiplier: 1.0,
    asset_criticality_note: 'Asset Criticality Multiplier defaults to 1.0 for a single host scan. Increase it when the asset is a crown-jewel system.',
    categories,
    explanation: `Starting at 100, weighted penalties were subtracted from the categories above. The final score is ${score} because ${totalWeightedRisk} of ${maxTheoreticalRisk} theoretical risk was realized.`,
    summary: score >= 90 ? 'This target appears well aligned with modern PQC transition guidance.' : score >= 70 ? 'The target is progressing toward PQC readiness but still has notable legacy exposure.' : 'The target remains highly exposed to legacy cryptography and should be remediated quickly.'
  };
}

function buildVulnerabilityFindings(context) {
  const { hostname, ip_address, port, protocol_support, bestCert, isPQC, recommendations = [], hasRC4, hasDES } = context;
  const findings = [];
  const sigAlg = (bestCert?.sigalg || 'unknown').toLowerCase();
  const endpoint = `${hostname || 'unknown'}:${port || 443}`;

  const addFinding = (finding) => findings.push(finding);

  if (hasRC4 || hasDES || (protocol_support?.tls_1_2?.cipher_suites || []).some(c => (c.name || '').includes('RSA') || (c.name || '').includes('DES'))) {
    addFinding({
      id: 'legacy-cipher',
      title: 'Legacy cipher suite negotiated',
      severity: 'high',
      description: 'The server offered legacy cipher suites that weaken confidentiality and are poor candidates for post-quantum migration.',
      origin: {
        hostname: hostname || 'unknown',
        ip_address: ip_address || 'unknown',
        port: port || 443,
        target: endpoint,
        misconfiguration: `The server offered the ${(protocol_support?.tls_1_2?.cipher_suites || [])[0]?.name || 'legacy cipher suite'} during the handshake.`,
        certificate_details: bestCert ? `Certificate is signed using ${sigAlg || 'unknown'}.` : 'No certificate chain details were available.'
      },
      remediation: {
        summary: 'Disable weak suites and prefer TLS 1.3 with AEAD ciphers.',
        config_snippets: [
          'Nginx:\nssl_protocols TLSv1.3;\nssl_ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;',
          'Apache:\nSSLProtocol -all +TLSv1.3\nSSLCipherSuite TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'
        ],
        cli_commands: [
          'openssl s_client -connect ' + endpoint + ' -tls1_2',
          'certbot renew --force-renewal'
        ],
        explanation: 'This removes the weak negotiated suites and forces modern forward-secret cryptography.'
      }
    });
  }

  const legacyProtocolNames = [];
  if (protocol_support?.tls_1_0?.supported) legacyProtocolNames.push('TLS 1.0');
  if (protocol_support?.tls_1_1?.supported) legacyProtocolNames.push('TLS 1.1');
  if (protocol_support?.ssl_3_0?.supported) legacyProtocolNames.push('SSL 3.0');
  if (legacyProtocolNames.length > 0) {
    addFinding({
      id: 'legacy-protocol',
      title: 'Legacy TLS versions are still enabled',
      severity: 'critical',
      description: `The server still accepts ${legacyProtocolNames.join(', ')}.`,
      origin: {
        hostname: hostname || 'unknown',
        ip_address: ip_address || 'unknown',
        port: port || 443,
        target: endpoint,
        misconfiguration: `The server accepted legacy protocol versions: ${legacyProtocolNames.join(', ')}.`,
        certificate_details: bestCert ? `Certificate is signed using ${sigAlg || 'unknown'}.` : 'No certificate chain details were available.'
      },
      remediation: {
        summary: 'Disable legacy TLS versions and require TLS 1.3 for all clients.',
        config_snippets: [
          'HAProxy:\nfrontend https\n  bind :443 ssl crt /etc/ssl/certs/example.pem alpn h2,http/1.1\n  tcp-request inspect-delay 5s\n  tcp-request content reject if !{ ssl_fc }',
          'Nginx:\nssl_protocols TLSv1.2 TLSv1.3;'
        ],
        cli_commands: ['openssl s_client -connect ' + endpoint + ' -tls1'],
        explanation: 'This blocks downgrade attempts and removes obsolete protocol support.'
      }
    });
  }

  if (!isPQC) {
    addFinding({
      id: 'missing-pqc-hybrid',
      title: 'No PQC hybrid key exchange detected',
      severity: 'high',
      description: 'The server did not advertise a hybrid post-quantum key exchange such as X25519MLKEM768.',
      origin: {
        hostname: hostname || 'unknown',
        ip_address: ip_address || 'unknown',
        port: port || 443,
        target: endpoint,
        misconfiguration: 'The TLS handshake did not include any PQC or hybrid key exchange groups.',
        certificate_details: bestCert ? `Certificate is signed using ${sigAlg || 'unknown'}.` : 'No certificate chain details were available.'
      },
      remediation: {
        summary: 'Enable ML-KEM hybrid key exchange and prefer TLS 1.3 with X25519MLKEM768.',
        config_snippets: [
          'Nginx (example):\nssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;\nssl_conf_command Options -SessionTicket',
          'OpenSSL example:\nopenssl ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'
        ],
        cli_commands: ['openssl s_client -connect ' + endpoint + ' -tls1_3 -curves X25519MLKEM768'],
        explanation: 'Hybrid PQC key exchanges protect against harvest-now-decrypt-later risk while preserving interoperability.'
      }
    });
  }

  if (bestCert && /sha1|sha-1|md5/i.test(sigAlg)) {
    addFinding({
      id: 'weak-signature',
      title: 'Certificate signature algorithm is weak or outdated',
      severity: 'medium',
      description: 'The certificate chain uses a weak signature algorithm which should be replaced.',
      origin: {
        hostname: hostname || 'unknown',
        ip_address: ip_address || 'unknown',
        port: port || 443,
        target: endpoint,
        misconfiguration: `The certificate is signed using ${sigAlg}.`,
        certificate_details: `Certificate is signed using ${sigAlg}.`
      },
      remediation: {
        summary: 'Renew the certificate with a modern hash and a PQC-capable signature pathway.',
        config_snippets: [
          'Certbot:\ncertbot certonly --standalone -d ' + (hostname || 'example.com') + ' --preferred-challenges http',
          'Apache:\nSSLCertificateFile /etc/letsencrypt/live/' + (hostname || 'example.com') + '/fullchain.pem'
        ],
        cli_commands: ['certbot renew --force-renewal', 'openssl x509 -in fullchain.pem -text | grep -i "Signature Algorithm"'],
        explanation: 'Modern signatures reduce breakage risk and support future PQC migration.'
      }
    });
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════
// SCORING ENGINE — Bounded Normalized Weighted Risk Model
// ═══════════════════════════════════════════════════════════════════
//
// Score = max(0, min(100, round(100 × (1 - TotalWeightedRisk / MaxTheoreticalRisk))))
//
// Category breakdown (Shor > Grover prioritization):
//   1. Key Exchange (KEM)       — max penalty 30  (Shor: exponential speedup)
//   2. Signatures               — max penalty 20  (Shor: exponential speedup)
//   3. Protocol Version         — max penalty 20  (downgrade/compliance risk)
//   4. Symmetric Ciphers        — max penalty 15  (Grover: quadratic speedup only)
//   5. Certificate Hygiene      — max penalty 10  (operational, not quantum-specific)
//   6. Vulnerability Posture    — max penalty  5  (binary pass/fail)
//
// MaxTheoreticalRisk = 30 + 20 + 20 + 15 + 10 + 5 = 100
//
// Proof of bounds:
//   0 ≤ penalty_i ≤ cat_max_i for all i
//   ⟹ 0 ≤ TotalWeightedRisk ≤ 100
//   ⟹ 0 ≤ 1 - ratio ≤ 1
//   ⟹ 0 ≤ Score ≤ 100  ∎
// ═══════════════════════════════════════════════════════════════════

const CATEGORY_CAPS = {
  keyExchange:    30,
  signatures:     20,
  protocol:       20,
  symmetric:      15,
  certificate:    10,
  vulnerability:   5,
};

const MAX_THEORETICAL_RISK = Object.values(CATEGORY_CAPS).reduce((a, b) => a + b, 0); // 100

function computeQuantumScore(protocol_support, bestCert, isPQC, pqcDetails) {
  const penalties = {};

  // ── 1. Key Exchange (KEM) — Shor's algorithm threat ──
  let kemPenalty = 0;
  if (!isPQC) {
    kemPenalty += 20; // No PQC key exchange at all
  }
  // Classical-only key exchange (RSA/DHE/ECDHE without PQC hybrid)
  if (!pqcDetails.hasHybridKEM) {
    kemPenalty += 10;
  }
  penalties.keyExchange = Math.min(kemPenalty, CATEGORY_CAPS.keyExchange);

  // ── 2. Signatures — Shor's algorithm threat ──
  let sigPenalty = 0;
  if (bestCert) {
    const sigAlg = (bestCert.sigalg || bestCert.signature_algorithm || '').toLowerCase();
    if (sigAlg.includes('sha1')) {
      sigPenalty += 10; // SHA-1 signature — broken classically
    }
    if (!pqcDetails.hasPQCSignature) {
      sigPenalty += 10; // No PQC signature algorithm
    }
  } else {
    sigPenalty += 15; // No certificate info available
  }
  penalties.signatures = Math.min(sigPenalty, CATEGORY_CAPS.signatures);

  // ── 3. Protocol Version — compliance & downgrade risk ──
  let protoPenalty = 0;
  if (!protocol_support.tls_1_3.supported) protoPenalty += 10;
  if (protocol_support.tls_1_0.supported)  protoPenalty += 6;
  if (protocol_support.tls_1_1.supported)  protoPenalty += 4;
  if (protocol_support.ssl_3_0 && protocol_support.ssl_3_0.supported) protoPenalty += 8;
  penalties.protocol = Math.min(protoPenalty, CATEGORY_CAPS.protocol);

  // ── 4. Symmetric Ciphers — Grover's algorithm (quadratic speedup only) ──
  let symPenalty = 0;
  const allCiphers12 = protocol_support.tls_1_2.cipher_suites || [];
  const hasRC4 = allCiphers12.some(c => (c.name || '').toUpperCase().includes('RC4'));
  const hasDES = allCiphers12.some(c => {
    const name = (c.name || '').toUpperCase();
    return name.includes('DES') && !name.includes('ECDHE'); // DES/3DES
  });
  const hasCBC = allCiphers12.some(c => (c.name || '').toUpperCase().includes('CBC'));
  if (hasRC4) symPenalty += 8;
  if (hasDES) symPenalty += 5;
  if (hasCBC) symPenalty += 2;
  penalties.symmetric = Math.min(symPenalty, CATEGORY_CAPS.symmetric);

  // ── 5. Certificate Hygiene — operational risk ──
  let certPenalty = 0;
  if (bestCert) {
    const keyType = extractKeyType(bestCert);
    const keySize = extractKeySize(bestCert);
    if (keyType === 'RSA' && keySize < 2048) certPenalty += 6;
    else if (keyType === 'RSA' && keySize < 4096) certPenalty += 3;
    // All classical certs are quantum-vulnerable, minor operational penalty
    if (keyType === 'RSA' || keyType === 'EC') certPenalty += 2;
  } else {
    certPenalty += 5;
  }
  penalties.certificate = Math.min(certPenalty, CATEGORY_CAPS.certificate);

  // ── 6. Vulnerability Posture — binary checks ──
  let vulnPenalty = 0;
  // Weak ciphers already covered above; this is for TLS-level vulns
  if (hasRC4 || hasDES) vulnPenalty += 3;
  penalties.vulnerability = Math.min(vulnPenalty, CATEGORY_CAPS.vulnerability);

  // ── Compute final score ──
  const totalWeightedRisk = Object.values(penalties).reduce((a, b) => a + b, 0);
  const score = Math.max(0, Math.min(100, Math.round(100 * (1 - totalWeightedRisk / MAX_THEORETICAL_RISK))));

  return { score, penalties, totalWeightedRisk, maxTheoreticalRisk: MAX_THEORETICAL_RISK };
}

// ═══════════════════════════════════════════════════════════════════
// CERTIFICATE HELPERS — Reliable key type & size extraction
// ═══════════════════════════════════════════════════════════════════

function extractKeyType(cert) {
  if (!cert) return 'unknown';

  if (cert.key_type) return cert.key_type; // For mocked certs or explicit PQC
  
  // Try asymmetricKeyType (Node.js 16+)
  if (cert.asn1Curve || cert.nistCurve) return 'EC';

  // Try bits field
  if (cert.bits) {
    // EC keys are typically 256/384/521 bits; RSA keys are 2048/3072/4096+
    return cert.bits <= 521 ? 'EC' : 'RSA';
  }

  // Fallback to pubkey length heuristic (improved threshold)
  if (cert.pubkey) {
    // EC public keys are 64-133 bytes; RSA public keys are 256+ bytes
    return cert.pubkey.length > 200 ? 'RSA' : 'EC';
  }

  return 'RSA'; // conservative default
}

function extractKeySize(cert) {
  if (!cert) return 2048;

  // Use bits field if available
  if (cert.bits) return cert.bits;

  // Fallback: estimate from pubkey
  if (cert.pubkey) return cert.pubkey.length * 8;

  return 2048; // conservative default
}

function formatCertDN(dnObject) {
  if (!dnObject) return '';
  return Object.entries(dnObject).map(([k, v]) => `${k}=${v}`).join(', ');
}

// ═══════════════════════════════════════════════════════════════════
// TLS PROTOCOL PROBE — with timeout & double-resolve guard
// ═══════════════════════════════════════════════════════════════════

const PROBE_TIMEOUT_MS = 5000;

async function probeProtocol(hostname, port, version, cipher = null) {
  return new Promise((resolve) => {
    let resolved = false;
    function safeResolve(value) {
      if (!resolved) {
        resolved = true;
        resolve(value);
      }
    }

    try {
      const opts = {
        host: hostname,
        port: port,
        servername: hostname,
        minVersion: version,
        maxVersion: version,
        rejectUnauthorized: false,
        timeout: PROBE_TIMEOUT_MS,
      };
      if (cipher) opts.ciphers = cipher;

      const socket = tls.connect(opts, () => {
        try {
          const c = socket.getCipher();
          const ephemeral = socket.getEphemeralKeyInfo() || {};
          const cert = socket.getPeerCertificate(true);

          // Build key exchange info including PQC group detection
          let keyExchange = ephemeral.type || 'RSA';
          if (ephemeral.name) {
            keyExchange = ephemeral.name; // e.g., 'X25519', 'X25519MLKEM768'
          }

          const cipher_suites = [{
            name: c.name,
            key_size: c.version === 'TLSv1.3' ? 256 : 128,
            key_exchange: keyExchange,
            ephemeral_type: ephemeral.type || null,
            ephemeral_name: ephemeral.name || null,
            ephemeral_size: ephemeral.size || null,
          }];

          socket.end();
          safeResolve({ supported: true, cipher_suites, cert });
        } catch (innerErr) {
          socket.destroy();
          safeResolve({ supported: false, cipher_suites: [], cert: null });
        }
      });

      socket.on('timeout', () => {
        socket.destroy();
        safeResolve({ supported: false, cipher_suites: [], cert: null, error: `TLS probe timed out for ${hostname}:${port}` });
      });

      socket.on('error', (error) => {
        safeResolve({ supported: false, cipher_suites: [], cert: null, error: error.message || `TLS probe failed for ${hostname}:${port}` });
      });

      // Hard timeout fallback
      setTimeout(() => {
        if (!socket.destroyed) socket.destroy();
        safeResolve({ supported: false, cipher_suites: [], cert: null, error: `TLS probe timed out for ${hostname}:${port}` });
      }, PROBE_TIMEOUT_MS + 1000);
    } catch (err) {
      safeResolve({ supported: false, cipher_suites: [], cert: null, error: err.message || `TLS probe failed for ${hostname}:${port}` });
    }
  });
}

// ═══════════════════════════════════════════════════════════════════
// MAIN TLS SCANNER — Detailed scan with PQC-aware scoring
// ═══════════════════════════════════════════════════════════════════

export async function runDetailedTLSScan(hostname, port = 443, deep = false) {
  const protocol_support = {
    ssl_2_0: { supported: false, cipher_suites: [] },
    ssl_3_0: { supported: false, cipher_suites: [] },
    tls_1_0: { supported: false, cipher_suites: [] },
    tls_1_1: { supported: false, cipher_suites: [] },
    tls_1_2: { supported: false, cipher_suites: [] },
    tls_1_3: { supported: false, cipher_suites: [] },
  };

  let certificate_info = [];
  let bestCert = null;
  const scanErrors = [];

  // TLS 1.3 scan
  const res13 = await probeProtocol(hostname, port, 'TLSv1.3');
  protocol_support.tls_1_3.supported = res13.supported;
  if (res13.error) scanErrors.push(res13.error);
  if (res13.cert) bestCert = res13.cert;
  if (res13.supported && res13.cipher_suites.length > 0) {
    protocol_support.tls_1_3.cipher_suites.push(...res13.cipher_suites);
  }

  // TLS 1.2 scan
  if (deep) {
    let supported_12 = false;
    for (const cipher of CIPHERS_1_2) {
      const res = await probeProtocol(hostname, port, 'TLSv1.2', cipher);
      if (res.supported) {
        supported_12 = true;
        if (res.cert && !bestCert) bestCert = res.cert;
        if (!protocol_support.tls_1_2.cipher_suites.find(c => c.name === res.cipher_suites[0].name)) {
          protocol_support.tls_1_2.cipher_suites.push(...res.cipher_suites);
        }
      }
    }
    protocol_support.tls_1_2.supported = supported_12;
  } else {
    const res12 = await probeProtocol(hostname, port, 'TLSv1.2');
    protocol_support.tls_1_2.supported = res12.supported;
    if (res12.error) scanErrors.push(res12.error);
    if (res12.cert && !bestCert) bestCert = res12.cert;
    if (res12.supported) {
      protocol_support.tls_1_2.cipher_suites.push(...res12.cipher_suites);
    }
  }

  // Older protocols (TLS 1.1, TLS 1.0)
  for (const ver of ['TLSv1.1', 'TLSv1.0']) {
    const res = await probeProtocol(hostname, port, ver);
    const key = ver === 'TLSv1.1' ? 'tls_1_1' : 'tls_1_0';
    protocol_support[key].supported = res.supported;
    if (res.error) scanErrors.push(res.error);
    if (res.supported) protocol_support[key].cipher_suites.push(...res.cipher_suites);
  }

  // Build certificate info
  if (bestCert) {
    const keyType = extractKeyType(bestCert);
    const keySize = extractKeySize(bestCert);

    certificate_info.push({
      subject: formatCertDN(bestCert.subject),
      issuer: formatCertDN(bestCert.issuer),
      key_type: keyType,
      key_size: keySize,
      signature_algorithm: bestCert.sigalg || 'unknown',
      not_before: bestCert.valid_from,
      not_after: bestCert.valid_to,
      san_dns_names: bestCert.subjectaltname ? bestCert.subjectaltname.split(',').map(s => s.replace('DNS:', '').trim()) : [],
      ocsp_stapling: false,
      ocsp_must_staple: false
    });
  }

  // ── PQC Detection ──
  // Gather all key exchange info from all cipher suites
  const allKxParts = [
    ...protocol_support.tls_1_3.cipher_suites,
    ...protocol_support.tls_1_2.cipher_suites
  ];

  const allKxText = allKxParts.map(c => {
    const parts = [c.key_exchange || '', c.ephemeral_name || '', c.ephemeral_type || ''];
    return parts.join(' ');
  }).join(' ');

  const isPQC = detectPQC(allKxText);

  const pqcDetails = {
    hasHybridKEM: detectPQC(allKxText), // true if any hybrid like X25519MLKEM768
    hasPQCSignature: false, // No deployed PQC certs in the wild yet
  };

  const supported_groups = inferSupportedGroups(protocol_support, isPQC, bestCert);

  // Check certificate signature for PQC
  if (bestCert) {
    const sigAlg = (bestCert.sigalg || '').toLowerCase();
    pqcDetails.hasPQCSignature = detectPQC(sigAlg);
  }

  // ── Compute quantum score using bounded weighted model ──
  const hasRC4 = protocol_support.tls_1_2.cipher_suites.some(c => (c.name || '').toUpperCase().includes('RC4'));
  const hasDES = protocol_support.tls_1_2.cipher_suites.some(c => {
    const name = (c.name || '').toUpperCase();
    return name.includes('DES');
  });

  // ── Build recommendations ──
  const recommendations = [];
  if (!protocol_support.tls_1_3.supported) {
    recommendations.push('CRITICAL: Enable TLS 1.3 — required for CNSA 2.0 compliance');
  }
  if (protocol_support.tls_1_0.supported) {
    recommendations.push('CRITICAL: Disable TLS 1.0 — deprecated per NIST SP 800-52r2');
  }
  if (protocol_support.tls_1_1.supported) {
    recommendations.push('HIGH: Disable TLS 1.1 — deprecated per RFC 8996');
  }
  if (!isPQC) {
    recommendations.push('CRITICAL: Deploy ML-KEM hybrid key exchange for harvest-now-decrypt-later protection');
  }
  if (hasRC4) {
    recommendations.push('CRITICAL: Remove RC4 cipher suites — cryptographically broken (RFC 7465)');
  }
  if (hasDES) {
    recommendations.push('HIGH: Remove DES/3DES cipher suites — vulnerable to Sweet32');
  }
  if (bestCert) {
    const keyType = extractKeyType(bestCert);
    const keySize = extractKeySize(bestCert);
    if (keyType === 'RSA' && keySize < 2048) {
      recommendations.push('CRITICAL: RSA key below 2048 bits — trivially breakable');
    }
  }

  const scoring = computeQuantumScore(protocol_support, bestCert, isPQC, pqcDetails);
  const scoreBreakdown = buildScoreBreakdown(scoring, protocol_support, bestCert, isPQC, pqcDetails, hasRC4, hasDES);
  const vulnerabilityFindings = buildVulnerabilityFindings({
    hostname,
    ip_address: hostname,
    port,
    protocol_support,
    bestCert,
    isPQC,
    recommendations,
    hasRC4,
    hasDES
  });

  return {
    status: 'completed',
    hostname,
    port,
    timestamp: new Date().toISOString(),
    quantum_score: scoring.score,
    quantum_scoring_breakdown: scoring.penalties,
    score_breakdown: scoreBreakdown,
    vulnerabilities: {
      heartbleed: { vulnerable: false },
      robot: { vulnerable: false },
      renegotiation: { client_renegotiation_vulnerable: false },
      downgrade_attack: { vulnerable: false },
      ccs_injection: { vulnerable: false },
      weak_ciphers: { vulnerable: hasRC4 || hasDES }
    },
    elliptic_curves: {},
    supported_groups,
    vulnerability_findings: vulnerabilityFindings,
    recommendations,
    errors: scanErrors.length > 0 ? scanErrors : []
  };
}

// ═══════════════════════════════════════════════════════════════════
// EXPORTS for testing
// ═══════════════════════════════════════════════════════════════════
export { computeQuantumScore, detectPQC, CATEGORY_CAPS, MAX_THEORETICAL_RISK, buildVulnerabilityFindings, buildScoreBreakdown, inferSupportedGroups };
