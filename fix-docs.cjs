const fs = require('fs');
let html = fs.readFileSync('public/docs.html', 'utf8');

// 1. Add marked.js
if (!html.includes('marked.min.js')) {
    html = html.replace('<script src="tailwind-config.js"></script>', '<script src="tailwind-config.js"></script>\n<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>');
}

// 2. Replace Sidebar
const sidebarStart = html.indexOf('<aside class="w-72 fixed left-0');
const sidebarEnd = html.indexOf('</aside>', sidebarStart) + 8;
const newSidebar = `
<aside class="w-72 fixed left-0 top-20 bottom-0 overflow-y-auto bg-surface-container-low border-r border-outline-variant/10 p-8 hidden md:block no-scrollbar">
    <div class="space-y-8">
        <section>
            <h5 class="font-label text-xs uppercase tracking-widest text-primary mb-4 opacity-70">Getting Started</h5>
            <ul class="space-y-3">
                <li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="01_System_Architecture.md">System Architecture</a></li>
                <li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="02_System_Requirements.md">System Requirements</a></li>
                <li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="05_Deployment_Guide.md">Deployment Guide</a></li>
            </ul>
        </section>
        <section>
            <h5 class="font-label text-xs uppercase tracking-widest text-primary mb-4 opacity-70">Core Concepts</h5>
            <ul class="space-y-3">
                <li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="03_Scoring_Methodology.md">Scoring Methodology</a></li>
                <li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="04_Security_and_Privacy.md">Security & Privacy</a></li>
                <li><a class="doc-link text-on-surface-variant hover:text-primary transition-colors text-sm cursor-pointer" data-file="06_Development_Roadmap.md">Development Roadmap</a></li>
            </ul>
        </section>
    </div>
    <div class="mt-12 p-4 rounded-xl bg-surface-container-highest/30 border border-outline-variant/10">
        <p class="text-[10px] font-mono text-secondary-fixed-dim/50 leading-relaxed">SYSTEM_STATUS: NOMINAL<br/>ENCRYPTION: QUANTUM_READY<br/>NODE_ID: 0x82...FA21</p>
    </div>
</aside>
`;
if (sidebarStart !== -1) {
    html = html.substring(0, sidebarStart) + newSidebar + html.substring(sidebarEnd);
}

// 3. Replace Main Content Area
const mainStart = html.indexOf('<div class="flex-1 px-6 md:px-12');
const mainEnd = html.indexOf('<!-- On This Page', mainStart);
const newMain = `
<div class="flex-1 px-6 md:px-12 lg:px-20 py-12 flex flex-col w-full max-w-full lg:max-w-[calc(100%-16rem)]">
    <div id="docs-loading" class="hidden flex-1 flex-col items-center justify-center min-h-[400px]">
        <div class="w-12 h-12 rounded-full border-2 border-primary/20 border-t-primary animate-spin mb-4"></div>
        <div class="text-primary font-mono text-xs tracking-widest">DECRYPTING DOCUMENT...</div>
    </div>
    <article id="docs-content" class="prose prose-invert max-w-none space-y-6 markdown-body w-full">
        <div class="p-12 text-center bg-surface-container-low rounded-2xl border border-outline-variant/10">
            <span class="material-symbols-outlined text-6xl text-primary/30 mb-4">menu_book</span>
            <h2 class="text-2xl font-bold mb-2">Documentation Hub</h2>
            <p class="text-on-surface-variant">Select a guide from the sidebar to begin reading.</p>
        </div>
    </article>
</div>

`;
if (mainStart !== -1 && mainEnd !== -1) {
    html = html.substring(0, mainStart) + newMain + html.substring(mainEnd);
}

// 4. Update the 'On This Page' section to be dynamic
const tocStart = html.indexOf('<aside class="hidden lg:block w-64');
const tocEnd = html.indexOf('</aside>', tocStart) + 8;
const newToc = `
<aside class="hidden xl:block w-64 p-12 border-l border-outline-variant/10 sticky top-20 h-[calc(100vh-5rem)] overflow-y-auto no-scrollbar shrink-0">
    <h5 class="font-label text-xs uppercase tracking-widest text-primary mb-6">On This Page</h5>
    <nav>
        <ul id="toc-list" class="space-y-4 text-sm">
            <!-- Generated dynamically -->
            <li class="text-on-surface-variant/50 italic text-xs">Waiting for content...</li>
        </ul>
    </nav>
</aside>
`;
if (tocStart !== -1 && tocEnd !== -1) {
    html = html.substring(0, tocStart) + newToc + html.substring(tocEnd);
}

// 5. Add Custom CSS and JS logic
const scriptBlock = `
<style>
    /* Markdown Styles */
    .markdown-body h1 { font-size: 2.5rem; font-weight: 800; margin-bottom: 1.5rem; color: #fff; letter-spacing: -0.025em; }
    .markdown-body h2 { font-size: 1.875rem; font-weight: 700; margin-top: 3rem; margin-bottom: 1.5rem; color: #fff; border-left: 4px solid #00D4FF; padding-left: 1rem; }
    .markdown-body h3 { font-size: 1.25rem; font-weight: 600; margin-top: 2rem; margin-bottom: 1rem; color: #E2E8F0; }
    .markdown-body p { margin-bottom: 1.5rem; line-height: 1.75; color: #94A3B8; font-size: 1rem; }
    .markdown-body ul { list-style-type: disc; padding-left: 1.5rem; margin-bottom: 1.5rem; color: #94A3B8; }
    .markdown-body ol { list-style-type: decimal; padding-left: 1.5rem; margin-bottom: 1.5rem; color: #94A3B8; }
    .markdown-body li { margin-bottom: 0.5rem; }
    .markdown-body strong { color: #F8FAFC; font-weight: 700; }
    .markdown-body table { width: 100%; text-align: left; border-collapse: collapse; margin-bottom: 2rem; font-size: 0.875rem; background: rgba(39,53,76,0.3); border-radius: 8px; overflow: hidden; }
    .markdown-body th { padding: 1rem; background: rgba(39,53,76,0.8); font-weight: 700; color: #00D4FF; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid rgba(255,255,255,0.05); }
    .markdown-body td { padding: 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); color: #CBD5E1; }
    .markdown-body tr:last-child td { border-bottom: none; }
    .markdown-body code { font-family: monospace; font-size: 0.875rem; background: rgba(0,212,255,0.1); color: #00D4FF; padding: 0.2rem 0.4rem; border-radius: 4px; }
    .markdown-body pre { background: #041329; border: 1px solid rgba(255,255,255,0.1); padding: 1.5rem; border-radius: 12px; overflow-x: auto; margin-bottom: 1.5rem; }
    .markdown-body pre code { background: transparent; color: #E2E8F0; padding: 0; border-radius: 0; }
    .markdown-body blockquote { border-left: 4px solid #00D4FF; padding-left: 1rem; margin-left: 0; color: #94A3B8; font-style: italic; background: rgba(0,212,255,0.05); padding: 1rem; border-radius: 0 8px 8px 0; }
    .markdown-body hr { border-color: rgba(255,255,255,0.1); margin: 3rem 0; }
    
    .toc-item.active { color: #00D4FF; font-weight: bold; border-left: 2px solid #00D4FF; padding-left: 8px; margin-left: -10px; }
    
    .doc-link.active-link {
        color: #00D4FF;
        font-weight: 700;
    }
    .doc-link.active-link::before {
        content: '';
        display: inline-block;
        width: 6px;
        height: 6px;
        background: #00D4FF;
        border-radius: 50%;
        margin-right: 8px;
        box-shadow: 0 0 8px rgba(0,212,255,0.8);
    }
    
    /* Responsive fixes */
    img { max-width: 100%; height: auto; }
</style>
<script>
    document.addEventListener('DOMContentLoaded', () => {
        const links = document.querySelectorAll('.doc-link');
        const contentArea = document.getElementById('docs-content');
        const loadingArea = document.getElementById('docs-loading');
        const tocList = document.getElementById('toc-list');
        
        async function loadMarkdown(filename, el) {
            links.forEach(l => l.classList.remove('active-link'));
            if (el) el.classList.add('active-link');
            
            contentArea.classList.add('hidden');
            loadingArea.classList.remove('hidden');
            loadingArea.classList.add('flex');
            
            try {
                const res = await fetch(\`/docs/\${filename}\`);
                if (!res.ok) throw new Error(\`Document \${filename} not found (\${res.status})\`);
                const mdText = await res.text();
                
                contentArea.innerHTML = marked.parse(mdText);
                
                generateTOC();
                
                window.scrollTo(0,0);
            } catch (err) {
                contentArea.innerHTML = \`<div class="p-8 border border-red-500/20 bg-red-500/5 rounded-xl"><h3 class="text-red-400 font-bold mb-2">Error Loading Document</h3><p class="text-on-surface-variant">\${err.message}</p></div>\`;
                if(tocList) tocList.innerHTML = '';
            } finally {
                loadingArea.classList.add('hidden');
                loadingArea.classList.remove('flex');
                contentArea.classList.remove('hidden');
            }
        }
        
        function generateTOC() {
            if(!tocList) return;
            const headings = contentArea.querySelectorAll('h2, h3');
            if (headings.length === 0) {
                tocList.innerHTML = '<li class="text-on-surface-variant/50 italic text-xs">No headings found</li>';
                return;
            }
            
            let tocHTML = '';
            headings.forEach((h, i) => {
                const id = 'heading-' + i;
                h.id = id;
                const isH3 = h.tagName.toLowerCase() === 'h3';
                const padding = isH3 ? 'pl-4' : '';
                const fontSize = isH3 ? 'text-xs text-on-surface-variant/70' : 'text-sm text-on-surface-variant font-medium';
                
                tocHTML += \`<li><a href="#\${id}" class="hover:text-primary transition-colors block py-1 \${padding} \${fontSize}">\${h.textContent}</a></li>\`;
            });
            tocList.innerHTML = tocHTML;
        }

        links.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const file = link.getAttribute('data-file');
                if(file) loadMarkdown(file, link);
            });
        });
        
        if (links.length > 0) {
            loadMarkdown(links[0].getAttribute('data-file'), links[0]);
        }
    });
</script>
</body>
`;

if (!html.includes('id="docs-loading"')) {
    html = html.replace('</body>', scriptBlock);
}
fs.writeFileSync('public/docs.html', html);
console.log('Docs updated successfully.');