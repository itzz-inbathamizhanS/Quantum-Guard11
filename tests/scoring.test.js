import test from 'node:test';
import assert from 'node:assert';
import { computeQuantumScore, detectPQC, CATEGORY_CAPS, MAX_THEORETICAL_RISK, buildVulnerabilityFindings } from '../src/scanner.js';

test('detectPQC correctly identifies PQC algorithms', () => {
  assert.strictEqual(detectPQC('X25519MLKEM768'), true);
  assert.strictEqual(detectPQC('TLS_AES_256_GCM_SHA384 ECDHE prime256v1'), false);
  assert.strictEqual(detectPQC('ML-DSA-65'), true);
  assert.strictEqual(detectPQC('FIPS203'), true);
  assert.strictEqual(detectPQC('RSA'), false);
});

test('computeQuantumScore: Perfect Score (TLS 1.3 + ML-KEM + ML-DSA)', () => {
  const protocol_support = {
    tls_1_3: { supported: true, cipher_suites: [{ name: 'TLS_AES_256_GCM_SHA384', key_exchange: 'X25519MLKEM768' }] },
    tls_1_2: { supported: false, cipher_suites: [] },
    tls_1_1: { supported: false, cipher_suites: [] },
    tls_1_0: { supported: false, cipher_suites: [] },
    ssl_3_0: { supported: false, cipher_suites: [] },
  };
  const bestCert = { key_type: 'PQC', bits: 256, sigalg: 'ML-DSA' };
  const isPQC = true;
  const pqcDetails = { hasHybridKEM: true, hasPQCSignature: true };

  const { score, penalties, totalWeightedRisk } = computeQuantumScore(protocol_support, bestCert, isPQC, pqcDetails);

  assert.strictEqual(score, 100);
  assert.strictEqual(totalWeightedRisk, 0);
  assert.strictEqual(penalties.keyExchange, 0);
  assert.strictEqual(penalties.signatures, 0);
  assert.strictEqual(penalties.protocol, 0);
  assert.strictEqual(penalties.symmetric, 0);
  assert.strictEqual(penalties.certificate, 0);
});

test('computeQuantumScore: High Risk Edge Case (never negative)', () => {
  const protocol_support = {
    tls_1_3: { supported: false, cipher_suites: [] }, // +10
    tls_1_2: { supported: true, cipher_suites: [{ name: 'TLS_RSA_WITH_RC4_128_MD5' }, { name: 'TLS_RSA_WITH_DES_CBC_SHA' }] }, // RC4: +8, DES: +5, CBC: +2 => +15
    tls_1_1: { supported: true, cipher_suites: [] }, // +4
    tls_1_0: { supported: true, cipher_suites: [] }, // +6
    ssl_3_0: { supported: true, cipher_suites: [] }, // +8 => protocol total: 28 => capped at 20
  };
  const bestCert = { key_type: 'RSA', bits: 1024, sigalg: 'SHA1WithRSA' }; // RSA < 2048: +6, +2 => 8. SHA1: +10 => 10
  const isPQC = false; // +20
  const pqcDetails = { hasHybridKEM: false, hasPQCSignature: false }; // +10, +10

  const { score, penalties, totalWeightedRisk } = computeQuantumScore(protocol_support, bestCert, isPQC, pqcDetails);

  // Score should be 4 (not negative, calculated as 100 - (96/100)*100 = 4)
  assert.strictEqual(score, 4);
  assert.strictEqual(totalWeightedRisk, 96); // We know it doesn't max out certificate and vulnerability perfectly.
});

test('computeQuantumScore: Boundary Exact max penalty', () => {
  const { score } = computeQuantumScore({
    tls_1_3: { supported: false },
    tls_1_2: { cipher_suites: [{ name: 'RC4' }, { name: 'DES' }, { name: 'CBC' }] },
    tls_1_1: { supported: true },
    tls_1_0: { supported: true },
    ssl_3_0: { supported: true },
  }, null, false, { hasHybridKEM: false, hasPQCSignature: false });

  // Score for this specific combination is 12 since no cert is provided (+5 penalty instead of +10)
  assert.strictEqual(score, 12);
});

test('buildVulnerabilityFindings enriches findings with origin and remediation data', () => {
  const findings = buildVulnerabilityFindings({
    hostname: 'legacy-api.example.com',
    ip_address: '203.0.113.10',
    port: 443,
    protocol_support: {
      tls_1_3: { supported: false, cipher_suites: [] },
      tls_1_2: { supported: true, cipher_suites: [{ name: 'TLS_RSA_WITH_RC4_128_SHA', key_exchange: 'RSA' }] },
      tls_1_1: { supported: true, cipher_suites: [] },
      tls_1_0: { supported: true, cipher_suites: [] },
      ssl_3_0: { supported: false, cipher_suites: [] },
    },
    bestCert: { sigalg: 'sha256WithRSAEncryption', subject: { CN: 'legacy-api.example.com' } },
    isPQC: false,
    pqcDetails: { hasHybridKEM: false, hasPQCSignature: false },
    hasRC4: true,
    hasDES: false,
    recommendations: ['CRITICAL: Disable legacy ciphers']
  });

  assert.ok(findings.length >= 2);
  const legacyCipherFinding = findings.find(item => item.id === 'legacy-cipher');
  assert.ok(legacyCipherFinding);
  assert.equal(legacyCipherFinding.origin.hostname, 'legacy-api.example.com');
  assert.equal(legacyCipherFinding.origin.port, 443);
  assert.ok(legacyCipherFinding.remediation.config_snippets.length >= 1);
  assert.ok(legacyCipherFinding.remediation.cli_commands.some(cmd => cmd.includes('certbot')) || legacyCipherFinding.remediation.cli_commands.some(cmd => cmd.includes('openssl')));
});
