import https from 'https';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION — Connection limits & safety bounds
// ═══════════════════════════════════════════════════════════════════
const REQUEST_TIMEOUT_MS = 10000;       // 10s per HTTPS request
const MAX_RESPONSE_BYTES = 100 * 1024;  // 100KB max response body
const MAX_SUBDOMAINS = 50;              // Hard cap on returned subdomains
const CONCURRENCY_LIMIT = 5;            // Max parallel TLS scans

// ═══════════════════════════════════════════════════════════════════
// CONCURRENCY BATCHER — Simple p-limit implementation
// ═══════════════════════════════════════════════════════════════════

/**
 * Run an array of async functions with a concurrency limit.
 * @param {Array<() => Promise>} tasks — array of zero-arg async functions
 * @param {number} limit — max concurrent tasks
 * @returns {Promise<Array>} — settled results (values or null on error)
 */
export async function batchAsync(tasks, limit = CONCURRENCY_LIMIT) {
  const results = new Array(tasks.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < tasks.length) {
      const i = nextIndex++;
      try {
        results[i] = await tasks[i]();
      } catch {
        results[i] = null;
      }
    }
  }

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

// ═══════════════════════════════════════════════════════════════════
// SAFE HTTPS FETCH — with timeout & response size limit
// ═══════════════════════════════════════════════════════════════════

function safeFetch(url, options = {}) {
  return new Promise((resolve) => {
    const req = https.get(url, { ...options, timeout: REQUEST_TIMEOUT_MS }, (res) => {
      // Check HTTP status
      if (res.statusCode !== 200) {
        res.resume(); // drain the response
        return resolve('');
      }

      let data = '';
      let bytesReceived = 0;

      res.on('data', (chunk) => {
        bytesReceived += chunk.length;
        if (bytesReceived > MAX_RESPONSE_BYTES) {
          res.destroy();
          return resolve(data); // return what we have so far
        }
        data += chunk;
      });

      res.on('end', () => resolve(data));
      res.on('error', () => resolve(''));
    });

    req.on('timeout', () => {
      req.destroy();
      resolve('');
    });

    req.on('error', () => resolve(''));

    // Hard timeout fallback
    setTimeout(() => {
      if (!req.destroyed) req.destroy();
      resolve('');
    }, REQUEST_TIMEOUT_MS + 2000);
  });
}

// ═══════════════════════════════════════════════════════════════════
// SUBDOMAIN SOURCES
// ═══════════════════════════════════════════════════════════════════

function fetchHackertarget(domain) {
  return new Promise(async (resolve) => {
    try {
      const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
      const data = await safeFetch(url);

      if (!data || data.includes('error')) return resolve([]);

      const subdomains = new Set();
      for (const line of data.split('\n')) {
        if (!line.trim()) continue;
        const parts = line.split(',');
        if (parts.length > 0 && parts[0].includes(domain)) {
          subdomains.add(parts[0].trim());
        }
      }
      resolve(Array.from(subdomains));
    } catch {
      resolve([]);
    }
  });
}

function fetchCertspotter(domain) {
  return new Promise(async (resolve) => {
    try {
      const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`;
      const data = await safeFetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });

      if (!data) return resolve([]);

      const json = JSON.parse(data);
      const subdomains = new Set();
      for (const cert of json) {
        if (cert.dns_names) {
          for (const name of cert.dns_names) {
            if (name.includes(domain) && !name.includes('*')) {
              subdomains.add(name);
            }
          }
        }
      }
      resolve(Array.from(subdomains));
    } catch {
      resolve([]);
    }
  });
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════

export async function findSubdomains(domain) {
  const [ht, cs] = await Promise.all([
    fetchHackertarget(domain),
    fetchCertspotter(domain)
  ]);

  const allSubdomains = new Set([...ht, ...cs]);
  return Array.from(allSubdomains).slice(0, MAX_SUBDOMAINS);
}
