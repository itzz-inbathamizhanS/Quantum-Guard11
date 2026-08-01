const fs = require('fs');
const path = require('path');
const dir = path.join(process.cwd(), 'public');
const files = fs.readdirSync(dir).filter(f => f.endsWith('.html'));

files.forEach(file => {
    const filePath = path.join(dir, file);
    let content = fs.readFileSync(filePath, 'utf-8');
    
    const lines = content.split('\n');
    let newLines = [];
    let modified = false;
    
    for (let i = 0; i < lines.length; i++) {
        newLines.push(lines[i]);
        if (lines[i].includes('href="docs.html"') && !lines[i].includes('border-b-2')) {
            if (i + 1 < lines.length && lines[i+1].includes('href="about.html"')) {
                // already there
            } else {
                let aboutLine = lines[i].replace('docs.html', 'about.html').replace('>Docs<', '>About<');
                newLines.push(aboutLine);
                modified = true;
            }
        }
    }
    
    if (modified) {
        fs.writeFileSync(filePath, newLines.join('\n'), 'utf-8');
        console.log('Modified ' + file);
    }
});
console.log('Done.');