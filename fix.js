const fs = require('fs');
let html = fs.readFileSync('public/tools.html', 'utf8');

const anchor = '<h3 style="color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 5px; font-size:16px;">Quantum Score Breakdown</h3>';
const idx = html.indexOf(anchor);

if (idx > 0) {
  const divIdx = html.lastIndexOf('<div style="flex:1;">', idx);
  const endDivIdx = html.lastIndexOf('</div>', divIdx);
  
  if (endDivIdx > 0) {
    const injection = `</div>
          </div>

          <div style="margin-bottom: 25px; page-break-inside: avoid;">
            <h3 style="color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 5px; font-size:16px;">Cryptographic Bill of Materials (Asset Inventory)</h3>
            <div style="width: 100%;">
              <table style="width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; word-wrap: break-word; word-break: break-word;">
                <thead>
                  <tr style="background: #f1f5f9; text-align: left; color:#475569;">
                    <th style="padding: 8px; border: 1px solid #cbd5e1; width: 15%;">Type</th>
                    <th style="padding: 8px; border: 1px solid #cbd5e1; width: 35%;">Algorithm</th>
                    <th style="padding: 8px; border: 1px solid #cbd5e1; width: 30%;">Location</th>
                    <th style="padding: 8px; border: 1px solid #cbd5e1; width: 20%;">Status</th>
                  </tr>
                </thead>
                <tbody>
                  \${bestCert ? (() => {
                    let certStatus = '✅ Safe';
                    if (bestCert.key_type === 'RSA' && bestCert.key_size < 2048) certStatus = '❌ Vulnerable';
                    else if (bestCert.key_type === 'RSA') certStatus = '⚠️ Classic';
                    return \`
                      <tr>
                        <td style="padding: 8px; border: 1px solid #cbd5e1; color:#0f172a; font-weight:500;">tls-certificate</td>
                        <td style="padding: 8px; border: 1px solid #cbd5e1; font-family: monospace; color:#0f172a;">\${bestCert.key_type} (\${bestCert.key_size || '?'} bits)</td>
                        <td style="padding: 8px; border: 1px solid #cbd5e1; color:#475569;">\${raw.hostname}:\${raw.port || 443}</td>
                        <td style="padding: 8px; border: 1px solid #cbd5e1; font-weight:bold; color:\${certStatus.includes('Vulnerable') ? '#F43F5E' : (certStatus.includes('Classic') ? '#F59E0B' : '#10B981')};\parseInt">\${certStatus}</td>
                      </tr>
                    \`;
                  })() : ''}
                  \${allCiphers.map(c => {
                    let status = '✅ Safe';
                    const kxStr = c.key_exchange ? (typeof c.key_exchange === 'object' ? JSON.stringify(c.key_exchange) : String(c.key_exchange)).toLowerCase() : '';
                    if (c.name.includes('RC4') || c.name.includes('DES')) status = '❌ Vulnerable';
                    else if (!kxStr || (!kxStr.includes('kyber') && !kxStr.includes('mceliece') && !kxStr.includes('dilithium'))) status = '⚠️ Classic';
                    return \`
                      <tr>
                        <td style="padding: 8px; border: 1px solid #cbd5e1; color:#0f172a; font-weight:500;">tls-cipher</td>
                        <td style="padding: 8px; border: 1px solid #cbd5e1; font-family: monospace; color:#0f172a; word-break: break-all;">\${c.name}</td>
                        <td style="padding: 8px; border: 1px solid #cbd5e1; color:#475569;">\${raw.hostname}:\${raw.port || 443} (\${c.protocol})</td>
                        <td style="padding: 8px; border: 1px solid #cbd5e1; font-weight:bold; color:\${status.includes('Vulnerable') ? '#F43F5E' : (status.includes('Classic') ? '#F59E0B' : '#10B981')};">\${status}</td>
                      </tr>
                    \`;
                  }).join('')}
                </tbody>
              </table>
            </div>
            \${(!bestCert && allCiphers.length === 0) ? '<p style="font-size:14px;">No cryptographic assets found.</p>' : ''}
          </div>

          <div style="display:flex; gap:20px; margin-bottom: 25px; page-break-inside: avoid;">
`;
    const firstHalf = html.substring(0, endDivIdx);
    const secondHalf = html.substring(endDivIdx + 6);
    fs.writeFileSync('public/tools.html', firstHalf + injection + secondHalf);
    console.log('Fixed');
  } else { console.log('end div not found'); }
} else { console.log('anchor not found'); }
