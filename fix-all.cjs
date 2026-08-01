const fs = require('fs');
const path = require('path');
const dir = path.join(process.cwd(), 'public');

// 1. Restore docs.html to pristine state (I'll just checkout all again)
// Actually I'll just write the correct docs.html completely since it's easy.

let files = fs.readdirSync(dir).filter(f => f.endsWith('.html'));

files.forEach(file => {
    const filePath = path.join(dir, file);
    let content = fs.readFileSync(filePath, 'utf-8');
    
    // Add ABOUT link to top nav
    if (content.includes('href="docs.html"')) {
        // Find docs link block
        // For standard nav
        content = content.replace(/<a class="text-\[#D6E3FF\]\/70 hover:text-\[#00D4FF\] transition-colors duration-300 font-\['Inter'\] tracking-tight" href="docs\.html">Docs<\/a>\n\s*<\/div>/, '<a class="text-[#D6E3FF]/70 hover:text-[#00D4FF] transition-colors duration-300 font-[\'Inter\'] tracking-tight" href="docs.html">Docs</a>\n<a class="text-[#D6E3FF]/70 hover:text-[#00D4FF] transition-colors duration-300 font-[\'Inter\'] tracking-tight" href="about.html">About</a>\n</div>');
        
        // For index.html
        content = content.replace(/<a class="text-\[#D6E3FF\]\/70 hover:text-\[#D6E3FF\] transition-colors" href="docs\.html">Docs<\/a>\n\s*<\/div>/, '<a class="text-[#D6E3FF]/70 hover:text-[#D6E3FF] transition-colors" href="docs.html">Docs</a>\n<a class="text-[#D6E3FF]/70 hover:text-[#D6E3FF] transition-colors" href="about.html">About</a>\n</div>');
        
        // For docs.html (active state)
        content = content.replace(/<a class="text-\[#00D4FF\] border-b-2 border-\[#00D4FF\] pb-1 font-bold font-\['Inter'\] tracking-tight" href="docs\.html">Docs<\/a>\n\s*<\/div>/, '<a class="text-[#00D4FF] border-b-2 border-[#00D4FF] pb-1 font-bold font-[\'Inter\'] tracking-tight" href="docs.html">Docs</a>\n<a class="text-[#D6E3FF]/70 hover:text-[#00D4FF] transition-colors duration-300 font-[\'Inter\'] tracking-tight" href="about.html">About</a>\n</div>');
    }
    
    // Fix leaderboard.html upper case DOCS
    if (file === 'leaderboard.html') {
        content = content.replace(/<a href="about\.html" class="text-sm font-bold text-on-surface-variant hover:text-primary transition-colors">DOCS<\/a>/, '<a href="about.html" class="text-sm font-bold text-on-surface-variant hover:text-primary transition-colors">ABOUT</a>');
        // also add to leaderboard if not present
        if (!content.includes('href="about.html"')) {
             content = content.replace(/<a href="docs\.html" class="text-sm font-bold text-on-surface-variant hover:text-primary transition-colors">DOCS<\/a>\n\s*<\/div>/, '<a href="docs.html" class="text-sm font-bold text-on-surface-variant hover:text-primary transition-colors">DOCS</a>\n<a href="about.html" class="text-sm font-bold text-on-surface-variant hover:text-primary transition-colors">ABOUT</a>\n</div>');
        }
    }
    
    // Fix Mobile Menu
    content = content.replace(/<a href="docs\.html"><span class="material-symbols-outlined">description<\/span> Docs<\/a>\n\s*<\/div>/, '<a href="docs.html"><span class="material-symbols-outlined">description</span> Docs</a>\n<a href="about.html"><span class="material-symbols-outlined">info</span> About</a>\n</div>');
    
    // Fix docs.html sidebar menu
    if (file === 'docs.html') {
        if (!content.includes('Scanner Documentation')) {
            const sidebarTarget = '<li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="06_Development_Roadmap.md">Development Roadmap</a></li>\n            </ul>\n        </section>\n    </div>';
            const sidebarReplacement = '<li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="06_Development_Roadmap.md">Development Roadmap</a></li>\n            </ul>\n        </section>\n        <section>\n            <h5 class="font-label text-xs uppercase tracking-widest text-primary mb-4 opacity-70">Scanner Documentation</h5>\n            <ul class="space-y-3">\n                <li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="08_Scanner_Types_and_Usage.md">Scanner Types & Usage</a></li>\n                <li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="09_TLS_Scanner_Deep_Dive.md">TLS Scanner Deep Dive</a></li>\n                <li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="10_System_Mechanics_and_Workflows.md">System Mechanics & Workflows</a></li>\n            </ul>\n        </section>\n    </div>';
            content = content.replace(sidebarTarget, sidebarReplacement);
        }
        
        // Remove 07_Scan_Score from docs.html if it exists
        content = content.replace(/<li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="07_Scan_Score_Calculation\.md">Scan Score Calculation<\/a><\/li>\n/g, '');
    }
    
    fs.writeFileSync(filePath, content, 'utf-8');
});
console.log('All menus fixed successfully.');
