const fs = require('fs');

const dbText = fs.readFileSync('src/database.json', 'utf-8');
const dbCache = JSON.parse(dbText);
let allDomains = Object.values(dbCache.leaderboard || {}).sort((a, b) => (b.score || 0) - (a.score || 0));
let groupedDomains = [];

function getRootDomain(domain) {
    if (!domain) return '';
    const parts = domain.split('.');
    if (parts.length <= 2) return domain;
    if (['co', 'com', 'org', 'net', 'edu', 'gov'].includes(parts[parts.length-2]) && parts.length > 2) {
        return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
}

function processDomains() {
    const groups = {};
    allDomains.forEach(d => {
        const root = getRootDomain(d.domain);
        if (!groups[root]) groups[root] = { root, subdomains: [], maxScore: -1, minScore: 101 };
        groups[root].subdomains.push(d);
        if (d.score > groups[root].maxScore) groups[root].maxScore = d.score;
        if (d.score < groups[root].minScore) groups[root].minScore = d.score;
    });
    
    groupedDomains = Object.values(groups).sort((a,b) => b.maxScore - a.maxScore);
}

const categories = [
    { id: 'core',          label: 'Quantum Secure',      range: [90, 100], color: '#10B981', icon: 'shield_with_heart' },
    { id: 'pqc',           label: 'PQC Transitioning',   range: [70, 89],  color: '#00D4FF', icon: 'verified_user' },
    { id: 'transitioning', label: 'Classic Secure',      range: [50, 69],  color: '#D2BBFF', icon: 'sync_alt' },
    { id: 'legacy',        label: 'Legacy / Vulnerable', range: [0, 49],   color: '#F59E0B', icon: 'warning' }
];

function getCategory(score) {
    return categories.find(c => score >= c.range[0] && score <= c.range[1]) || categories[3];
}

try {
    processDomains();
    console.log('Grouped domains:', groupedDomains.length);
    groupedDomains.forEach(group => {
        const cat = getCategory(group.maxScore);
        const hasSubs = group.subdomains.length > 1 || group.subdomains[0].domain !== group.root;
        const rootItem = group.subdomains.find(s => s.domain === group.root) || group.subdomains[0];
        
        const html = `
            ${group.subdomains.sort((a,b) => b.score - a.score).map(sub => {
                const subCat = getCategory(sub.score);
                return subCat.label;
            }).join('')}
        `;
    });
    console.log('Template render ok!');
} catch (e) {
    console.error('Error in rendering:', e.message);
    console.error(e.stack);
}
