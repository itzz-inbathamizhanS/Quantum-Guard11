import https from 'https';
import dns from 'dns';

// P-04: Helper to wrap https.get with a timeout
function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
  return new Promise((resolve) => {
    try {
      const req = https.get(url, options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ statusCode: res.statusCode, data }));
      });
      req.on('error', () => resolve({ statusCode: 0, data: '' }));
      req.setTimeout(timeoutMs, () => { req.destroy(); resolve({ statusCode: 0, data: '' }); });
    } catch (err) {
      resolve({ statusCode: 0, data: '' });
    }
  });
}

function fetchHackertarget(domain) {
  return new Promise(async (resolve) => {
    try {
      const { statusCode, data } = await fetchWithTimeout(
        `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`
      );
      if (statusCode !== 200 || data.includes('error')) return resolve([]);
      const subdomains = new Set();
      for (const line of data.split('\n')) {
        if (!line.trim()) continue;
        const parts = line.split(',');
        if (parts.length > 0 && parts[0].includes(domain)) {
          subdomains.add(parts[0].trim());
        }
      }
      resolve(Array.from(subdomains));
    } catch (err) { resolve([]); }
  });
}

function fetchCertspotter(domain) {
  return new Promise(async (resolve) => {
    try {
      const { statusCode, data } = await fetchWithTimeout(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
        { headers: { 'User-Agent': 'Mozilla/5.0' } }
      );
      if (statusCode !== 200) return resolve([]);
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
    } catch (err) { resolve([]); }
  });
}

function fetchCrtSh(domain) {
  return new Promise(async (resolve) => {
    try {
      const { statusCode, data } = await fetchWithTimeout(
        `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
        {},
        10000 // crt.sh can be slow
      );
      if (statusCode !== 200) return resolve([]);
      const json = JSON.parse(data);
      const subdomains = new Set();
      for (const entry of json) {
        if (entry.name_value) {
          for (const name of entry.name_value.split('\n')) {
            const cleaned = name.trim().toLowerCase();
            if (cleaned.endsWith(domain) && !cleaned.includes('*')) {
              subdomains.add(cleaned);
            }
          }
        }
      }
      resolve(Array.from(subdomains));
    } catch (err) { resolve([]); }
  });
}

function fetchAlienVault(domain) {
  return new Promise(async (resolve) => {
    try {
      const { statusCode, data } = await fetchWithTimeout(
        `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`
      );
      if (statusCode !== 200) return resolve([]);
      const json = JSON.parse(data);
      const subdomains = new Set();
      if (json.passive_dns) {
        for (const entry of json.passive_dns) {
          if (entry.hostname && entry.hostname.endsWith(domain) && !entry.hostname.includes('*')) {
            subdomains.add(entry.hostname.toLowerCase());
          }
        }
      }
      resolve(Array.from(subdomains));
    } catch (err) { resolve([]); }
  });
}

// C-09: Try DNS resolution first, fall back to injecting common prefixes
// This way we verify which common subdomains actually resolve
async function checkCommonSubdomains(domain) {
  const commonPrefixes = ['www', 'mail', 'api', 'dev', 'test', 'circular', 'admin', 'vpn', 'secure', 'remote', 'portal', 'webmail'];
  const found = [];
  
  await Promise.all(commonPrefixes.map(async (prefix) => {
    const sub = `${prefix}.${domain}`;
    try {
      await dns.promises.resolve(sub);
      found.push(sub);
    } catch (e) {
      // DNS resolution failed — still inject the subdomain so TLS scanner can try it
      // The scanner will safely mark unreachable ones as "Failed"
      found.push(sub);
    }
  }));
  
  return found;
}

export async function findSubdomains(domain) {
  const [ht, cs, crt, av, brute] = await Promise.all([
    fetchHackertarget(domain),
    fetchCertspotter(domain),
    fetchCrtSh(domain),
    fetchAlienVault(domain),
    checkCommonSubdomains(domain)
  ]);
  
  const allSubdomains = new Set([...ht, ...cs, ...crt, ...av, ...brute]);
  return Array.from(allSubdomains).slice(0, 500);
}
