const fs = require('fs');
const path = require('path');

const dir = path.join(process.cwd(), 'public');
const files = fs.readdirSync(dir).filter(f => f.endsWith('.html'));

const standardNav = (filename) => {
    // Map filename to its data-nav identifier
    let activeNav = '';
    if (filename === 'index.html') activeNav = 'index';
    else if (filename === 'quick-assessment.html') activeNav = 'assessment';
    else if (filename === 'comprehensive-assessment.html') activeNav = 'assessment'; // Same section
    else if (filename === 'results.html') activeNav = 'results';
    else if (filename === 'compliance.html') activeNav = 'compliance';
    else if (filename === 'tools.html' || filename === 'tools_recovered.html') activeNav = 'tools';
    else if (filename === 'leaderboard.html') activeNav = 'leaderboard';
    else if (filename === 'docs.html') activeNav = 'docs';
    else if (filename === 'about.html') activeNav = 'about';

    const getClasses = (nav) => {
        if (nav === activeNav) {
            return `text-[#00D4FF] border-b-2 border-[#00D4FF] pb-1 font-bold transition-colors duration-300`;
        }
        return `text-[#D6E3FF]/70 hover:text-[#00D4FF] transition-colors duration-300`;
    };

    return `<!-- TopNavBar Standardized -->
<nav class="fixed top-0 w-full z-50 bg-[#041329]/80 backdrop-blur-xl border-b border-[#3C494E]/15 shadow-[0_8px_32px_0_rgba(0,212,255,0.08)] flex justify-between items-center px-4 md:px-8 h-20">
    <div class="flex items-center gap-8">
        <a href="index.html" class="text-2xl font-black tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-[#A8E8FF] to-[#00D4FF] font-headline flex items-center gap-2">
            <span class="material-symbols-outlined text-[#00D4FF] hidden sm:block" style="font-variation-settings: 'FILL' 1;">security</span>
            QuantumGuard
        </a>
        <div class="hidden lg:flex gap-6 items-center font-['Inter'] tracking-tight font-medium text-sm">
            <a class="${getClasses('index')}" href="index.html">Home</a>
            <a class="${getClasses('assessment')}" href="quick-assessment.html">Assessment</a>
            <a class="${getClasses('results')}" href="results.html">Results</a>
            <a class="${getClasses('compliance')}" href="compliance.html">Compliance</a>
            <a class="${getClasses('tools')}" href="tools.html">Tools</a>
            <a class="${getClasses('leaderboard')}" href="leaderboard.html">Leaderboard</a>
            <a class="${getClasses('docs')}" href="docs.html">Docs</a>
            <a class="${getClasses('about')}" href="about.html">About</a>
        </div>
    </div>
    <div class="flex items-center gap-4">
        <button class="hidden sm:block p-2 rounded-full hover:bg-[#27354C]/50 transition-all"><span class="material-symbols-outlined text-[#00D4FF]">notifications</span></button>
        <button class="hidden sm:block p-2 rounded-full hover:bg-[#27354C]/50 transition-all"><span class="material-symbols-outlined text-[#00D4FF]">account_circle</span></button>
        <button id="mobileMenuBtn" class="lg:hidden p-2 hover:bg-[#27354C]/50 rounded-lg transition-all" aria-label="Open menu">
            <span class="material-symbols-outlined text-[#D6E3FF]">menu</span>
        </button>
    </div>
</nav>
<!-- Mobile Menu Overlay -->
<div id="mobileOverlay" class="mobile-menu-overlay hidden fixed inset-0 bg-[#041329]/80 backdrop-blur-sm z-[51]"></div>
<div id="mobileDrawer" class="mobile-menu-drawer fixed top-0 right-0 h-full w-64 bg-surface-container shadow-2xl z-[52] transform translate-x-full transition-transform duration-300 p-6 flex flex-col gap-4">
    <div class="flex justify-between items-center mb-4">
        <span class="text-lg font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#A8E8FF] to-[#00D4FF]">Menu</span>
        <button id="mobileCloseBtn" class="p-2 hover:bg-[#27354C]/50 rounded-lg"><span class="material-symbols-outlined text-[#D6E3FF]">close</span></button>
    </div>
    <a href="index.html" class="flex items-center gap-3 text-[#D6E3FF] hover:text-[#00D4FF] py-2"><span class="material-symbols-outlined">home</span> Home</a>
    <a href="quick-assessment.html" class="flex items-center gap-3 text-[#D6E3FF] hover:text-[#00D4FF] py-2"><span class="material-symbols-outlined">quiz</span> Assessment</a>
    <a href="results.html" class="flex items-center gap-3 text-[#D6E3FF] hover:text-[#00D4FF] py-2"><span class="material-symbols-outlined">assessment</span> Results</a>
    <a href="compliance.html" class="flex items-center gap-3 text-[#D6E3FF] hover:text-[#00D4FF] py-2"><span class="material-symbols-outlined">verified</span> Compliance</a>
    <a href="tools.html" class="flex items-center gap-3 text-[#D6E3FF] hover:text-[#00D4FF] py-2"><span class="material-symbols-outlined">build</span> Tools</a>
    <a href="leaderboard.html" class="flex items-center gap-3 text-[#D6E3FF] hover:text-[#00D4FF] py-2"><span class="material-symbols-outlined">leaderboard</span> Leaderboard</a>
    <a href="docs.html" class="flex items-center gap-3 text-[#D6E3FF] hover:text-[#00D4FF] py-2"><span class="material-symbols-outlined">description</span> Docs</a>
    <a href="about.html" class="flex items-center gap-3 text-[#D6E3FF] hover:text-[#00D4FF] py-2"><span class="material-symbols-outlined">info</span> About</a>
</div>`;
};

files.forEach(file => {
    const filePath = path.join(dir, file);
    let content = fs.readFileSync(filePath, 'utf-8');
    
    // Attempt to extract existing <nav> block
    // Nav blocks might vary, we can use a regex to match from <nav to </nav>
    // Note: some files might have multiple <nav> elements (e.g. pagination), 
    // but the top navbar is always the first one.
    
    const navMatch = content.match(/<nav\b[^>]*>[\s\S]*?<\/nav>/);
    if (!navMatch) {
        console.log(`No <nav> found in ${file}`);
        return;
    }
    
    // Also, if there are mobile menu blocks, remove them so we don't have duplicates
    // Specifically looking for `<div id="mobileOverlay"...` and `<div id="mobileDrawer"...`
    content = content.replace(/<!-- Mobile Menu Overlay -->[\s\S]*?<div id="mobileDrawer"[\s\S]*?<\/div>\s*<\/div>/g, ''); // older index.html format
    content = content.replace(/<div id="mobileOverlay"[\s\S]*?<\/div>/g, '');
    content = content.replace(/<div id="mobileDrawer"[\s\S]*?<a href="about\.html"[\s\S]*?<\/a>\n\s*<\/div>/g, '');

    // Sometimes the older mobile drawer is just replaced up to the end of the div
    // Let's just do a simpler targeted removal of the old mobile drawer
    // Since we are adding our own mobile drawer with the nav
    
    // Let's replace the first nav with standardNav
    const newNav = standardNav(file);
    content = content.replace(navMatch[0], newNav);
    
    // Ensure padding on main content for files that didn't have a fixed nav before (leaderboard)
    if (file === 'leaderboard.html') {
        content = content.replace('<main class="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 py-8 relative">', '<main class="pt-24 flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 py-8 relative">');
    }
    
    fs.writeFileSync(filePath, content, 'utf-8');
    console.log(`Standardized nav in ${file}`);
});
