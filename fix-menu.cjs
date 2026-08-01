const fs = require('fs');
const path = require('path');
const dir = path.join(process.cwd(), 'public');
const files = fs.readdirSync(dir).filter(f => f.endsWith('.html'));

files.forEach(file => {
    const filePath = path.join(dir, file);
    let content = fs.readFileSync(filePath, 'utf-8');
    
    const lines = content.split('\n');
    let modified = false;
    
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('href="about.html"')) {
            if (lines[i].includes(' Docs</a>')) {
                lines[i] = lines[i].replace(' Docs</a>', ' About</a>');
                modified = true;
            }
            if (lines[i].includes('>description<')) {
                lines[i] = lines[i].replace('>description<', '>info<');
                modified = true;
            }
        }
    }
    
    if (modified) {
        fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
        console.log('Fixed ' + file);
    }
});