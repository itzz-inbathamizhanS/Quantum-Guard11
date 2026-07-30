import express from 'express';
import cors from 'cors';
import { GoogleGenAI } from '@google/genai';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { saveResult, getLeaderboard } from './leaderboard.js';

dotenv.config();

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
    const { hostname } = req.body;
    if (!hostname) return res.status(400).json({ error: 'hostname required' });

    const { findSubdomains } = await import('./subdomains.js');
    let subdomainsList = await findSubdomains(hostname);
    
    if (subdomainsList.length === 0) {
      subdomainsList.push(`www.${hostname}`, `api.${hostname}`);
    }

    subdomainsList = subdomainsList.slice(0, 15);
    
    const leaderData = getLeaderboard();
    const { runDetailedTLSScan } = await import('./scanner.js');

    await Promise.all(subdomainsList.map(async (sub) => {
      if (!leaderData.find(d => d.domain === sub)) {
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
        } catch(e) {}
      }
    }));

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

    res.json({
      domain: hostname,
      subdomains: formattedSubdomains
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/scan', async (req, res) => {
  try {
    const { hostname, port = 443, deep = false } = req.body;
    if (!hostname) return res.status(400).json({ error: 'hostname required' });
    
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
    
    res.json(result);
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
