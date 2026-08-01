import express from 'express';
import cors from 'cors';
import { GoogleGenAI } from '@google/genai';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { saveResult, getLeaderboard } from './leaderboard.js';

function buildSubdomainVariance(subdomains) {
  const numericScores = subdomains
    .map(item => Number(item?.score ?? item?.report?.quantum_score ?? 0))
    .filter(value => Number.isFinite(value));

  if (numericScores.length === 0) {
    return {
      domain_average: 0,
      lowest_baseline: 0,
      variance: 0,
      warning: false,
      explanation: 'No subdomain scores were available.'
    };
  }

  const domainAverage = Math.round(numericScores.reduce((sum, value) => sum + value, 0) / numericScores.length);
  const lowestBaseline = Math.min(...numericScores);
  const variance = Math.max(...numericScores) - lowestBaseline;
  const warning = variance >= 20;

  return {
    domain_average: domainAverage,
    lowest_baseline: lowestBaseline,
    variance,
    warning,
    explanation: warning
      ? 'Variance is high across subdomains; the weakest link should be treated as the organization baseline.'
      : 'Subdomain scores are consistent, so the organization posture is relatively uniform.'
  };
}

dotenv.config();

// Hostname validation — prevents injection & abuse
const HOSTNAME_RE = /^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/;
function isValidHostname(h) {
  if (!h || typeof h !== 'string') return false;
  const clean = h.trim().toLowerCase();
  return HOSTNAME_RE.test(clean) && clean.length <= 253;
}
function sanitizeHostname(h) {
  let clean = (h || '').trim().toLowerCase();
  // Strip protocol prefixes
  ['https://', 'http://'].forEach(p => { if (clean.startsWith(p)) clean = clean.slice(p.length); });
  // Strip trailing path/slash
  clean = clean.split('/')[0];
  return clean;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

const SYSTEM_PROMPT = `You are QuantumGuard Security Advisor, a Senior Security Engineer specializing in TLS/SSL configurations, post-quantum cryptography (PQC), and web PKI.

RULES:
- You ONLY discuss the provided scan report and general web/TLS security topics.
- If the user asks about anything unrelated (cooking, games, coding unrelated to security), politely decline: "I'm specialized in analyzing your QuantumGuard scan results. Let's focus on securing your infrastructure!"
- Always reference specific findings from the report (hostnames, cipher suites, scores) when giving advice.
- Provide step-by-step remediation with exact config snippets (Nginx, Apache, HAProxy) when applicable.
- Use markdown formatting: headers, bold, code blocks, numbered lists.
- Be concise but thorough. Prioritize critical vulnerabilities first.`;

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok', 
    service: 'QuantumGuard API',
    capabilities: ['tls_scan', 'chat_advisor', 'subdomain_discovery', 'leaderboard_sync']
  });
});

app.post('/api/subdomains', async (req, res) => {
  try {
    const rawHostname = req.body.hostname;
    if (!rawHostname) return res.status(400).json({ error: 'hostname required' });

    const hostname = sanitizeHostname(rawHostname);
    if (!isValidHostname(hostname)) {
      return res.status(400).json({ error: 'Invalid hostname format' });
    }

    const { findSubdomains, batchAsync } = await import('./subdomains.js');
    let subdomainsList = await findSubdomains(hostname);
    
    if (subdomainsList.length === 0) {
      subdomainsList.push(`www.${hostname}`, `api.${hostname}`);
    }

    subdomainsList = subdomainsList.slice(0, 15);
    
    const leaderData = getLeaderboard();
    const { runDetailedTLSScan } = await import('./scanner.js');

    // Use batched scanning to limit concurrency (max 5 simultaneous)
    const scanTasks = subdomainsList
      .filter(sub => !leaderData.find(d => d.domain === sub))
      .map(sub => async () => {
        try {
          const result = await runDetailedTLSScan(sub, 443, false);
          const score = result.quantum_score || 0;
          const maturity = score >= 90 ? 'Quantum Secure' : score >= 70 ? 'PQC Transitioning' : score >= 50 ? 'Classic Secure' : 'Legacy / Vulnerable';
          saveResult(sub, {
            domain: sub,
            score: score,
            maturity_level: maturity,
            timestamp: result.timestamp,
            report: result
          });
        } catch(e) {
          // Individual subdomain scan failure is non-fatal
          console.warn(`[SubdomainScan] Failed for ${sub}: ${e.message}`);
        }
      });

    await batchAsync(scanTasks, 5);

    const updatedLeaderData = getLeaderboard();
    
    // Map to the expected format and inject db results
    const formattedSubdomains = subdomainsList.map(sub => {
      const scanResult = updatedLeaderData.find(d => d.domain === sub);
      return {
        name: sub,
        active: true,
        score: scanResult ? scanResult.score : 0,
        maturity_level: scanResult ? scanResult.maturity_level : null,
        report: scanResult ? scanResult.report : null
      };
    });

    const variance = buildSubdomainVariance(formattedSubdomains);

    res.json({
      domain: hostname,
      subdomains: formattedSubdomains,
      subdomain_variance: variance
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/scan', async (req, res) => {
  try {
    const { port = 443, deep = false } = req.body;
    const rawHostname = req.body.hostname;
    if (!rawHostname) return res.status(400).json({ error: 'hostname required' });

    const hostname = sanitizeHostname(rawHostname);
    if (!isValidHostname(hostname)) {
      return res.status(400).json({ error: 'Invalid hostname format' });
    }
    
    // Import dynamically so it works if file was just created
    const { runDetailedTLSScan } = await import('./scanner.js');
    const result = await runDetailedTLSScan(hostname, port, deep);
    
    // Save to local JSON db
    const score = result.quantum_score || 0;
    const maturity = score >= 90 ? 'Quantum Secure' : score >= 70 ? 'PQC Transitioning' : score >= 50 ? 'Classic Secure' : 'Legacy / Vulnerable';
    saveResult(hostname, {
      domain: hostname,
      score: score,
      maturity_level: maturity,
      timestamp: result.timestamp,
      report: result
    });
    
    const overview = {
      score_breakdown: result.score_breakdown,
      vulnerability_findings: result.vulnerability_findings || [],
      supported_groups: result.supported_groups || [],
      subdomain_variance: result.subdomain_variance || null
    };

    res.json({ ...result, ...overview });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/leaderboard', (req, res) => {
  res.json(getLeaderboard());
});

app.post('/api/chat', async (req, res) => {
  try {
    const { message, reportContext, history } = req.body;
    
    if (!process.env.GEMINI_API_KEY) {
      return res.status(500).send("[ERROR] GEMINI_API_KEY environment variable is not set.");
    }

    const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

    // Truncate report context
    let context_json = JSON.stringify(reportContext || {});
    if (context_json.length > 8000) {
        context_json = context_json.substring(0, 8000) + '...(truncated)';
    }
    const context_part = `SCAN REPORT DATA:\n${context_json}\n\n`;

    // Map history to GoogleGenAI format
    let contents = [];
    if (history && Array.isArray(history)) {
      history.forEach(msg => {
        contents.push({
          role: msg.role === 'user' ? 'user' : 'model',
          parts: [{ text: msg.content || '' }]
        });
      });
    }

    // Add current user message with context
    contents.push({
      role: 'user',
      parts: [{ text: context_part + "USER MESSAGE: " + message }]
    });

    res.setHeader('Content-Type', 'text/plain');

    const responseStream = await ai.models.generateContentStream({
      model: 'gemini-flash-latest',
      contents: contents,
      config: {
        systemInstruction: SYSTEM_PROMPT
      }
    });

    for await (const chunk of responseStream) {
      if (chunk.text) {
        res.write(chunk.text);
      }
    }
    res.end();
  } catch (err) {
    console.error(err);
    res.write(`\n\n**Error:** ${err.message}`);
    res.end();
  }
});

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../public')));

// Fallback for SPA routing if needed (though it looks like standard HTML pages)
app.get('*all', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
