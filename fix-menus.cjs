const fs = require('fs');
const path = require('path');
const dir = path.join(process.cwd(), 'public');
const files = fs.readdirSync(dir).filter(f => f.endsWith('.html'));

files.forEach(file => {
    const filePath = path.join(dir, file);
    let content = fs.readFileSync(filePath, 'utf-8');
    
    let modified = false;
    
    // Fix desktop menu
    if (content.includes('href="about.html"') && content.includes('>Docs<')) {
        // Some replacements might have created "<a class=... href=about.html>Docs</a>"
        // Let's use a regex to fix it across the board
        content = content.replace(/href="about\.html">Docs<\/a>/g, 'href="about.html">About</a>');
        modified = true;
    }
    
    // Fix mobile menu
    const target = '<a href="about.html"><span class="material-symbols-outlined">description</span> Docs</a>';
    const replacement = '<a href="about.html"><span class="material-symbols-outlined">info</span> About</a>';
    
    if (content.includes(target)) {
        content = content.replace(target, replacement);
        modified = true;
    }
    
    if (modified) {
        fs.writeFileSync(filePath, content, 'utf-8');
        console.log('Fixed menus in ' + file);
    }
});