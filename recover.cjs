const fs = require('fs');
const path = require('path');

const logPath = "C:\\Users\\tamil\\.gemini\\antigravity\\brain\\a7640313-1bf6-4b61-910f-d05f88ed04cb\\.system_generated\\logs\\transcript_full.jsonl";
const targetTime = new Date('2026-08-01T22:15:00Z'); // Approx 3:45 AM local (+5:30)

const lines = fs.readFileSync(logPath, 'utf8').split('\n');

const allowedFiles = [
    'a:\\Quantum-Guard\\public\\tools.html',
    'a:\\Quantum-Guard\\public\\scanner-engine.js',
    'a:\\Quantum-Guard\\src\\scanner.js',
    'a:\\Quantum-Guard\\src\\server.js',
    'a:\\Quantum-Guard\\public\\docs.html'
];

for (const line of lines) {
    if (!line.trim()) continue;
    let entry;
    try {
        entry = JSON.parse(line);
    } catch (e) {
        continue;
    }
    
    // Stop if we passed the target time
    if (new Date(entry.created_at) > targetTime) {
        // Wait, the timestamp in UTC for 3:42 AM IST is 22:12 previous day. 
        console.log("Reached target time, stopping.");
        break;
    }

    if (entry.type === 'PLANNER_RESPONSE' && entry.tool_calls) {
        for (const call of entry.tool_calls) {
            const name = call.name || call.function?.name;
            let args = call.args || call.arguments || call.function?.arguments;
            if (!args) continue;
            
            let parsedArgs = args;
            if (typeof args === 'string') {
                try {
                    parsedArgs = JSON.parse(args);
                } catch(e) { continue; }
            }
            
            const targetFile = parsedArgs.TargetFile;
            if (targetFile && allowedFiles.some(f => targetFile.toLowerCase() === f.toLowerCase())) {
                const filePath = targetFile.replace('a:\\Quantum-Guard\\', './');
                
                if (name.includes('write_to_file')) {
                    console.log(`Writing to ${filePath}`);
                    fs.writeFileSync(filePath, parsedArgs.CodeContent);
                } 
                else if (name.includes('replace_file_content')) {
                    console.log(`Replacing in ${filePath}`);
                    if (fs.existsSync(filePath)) {
                        let content = fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
                        const rawTarget = parsedArgs.TargetContent || parsedArgs.targetContent || '';
                        const rawReplacement = parsedArgs.ReplacementContent || parsedArgs.replacementContent || '';
                        const target = rawTarget.replace(/\r\n/g, '\n');
                        const replacement = rawReplacement.replace(/\r\n/g, '\n');
                        if (content.includes(target)) {
                            content = content.replace(target, replacement);
                            fs.writeFileSync(filePath, content);
                            console.log(`Successfully replaced in ${filePath}`);
                        } else {
                            console.log(`[!] Target content not found in ${filePath}`);
                        }
                    }
                }
                else if (name.includes('multi_replace_file_content')) {
                    console.log(`Multi-replacing in ${filePath}`);
                    if (fs.existsSync(filePath)) {
                        let content = fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
                        for (const chunk of parsedArgs.ReplacementChunks || parsedArgs.replacementChunks || []) {
                            const rawTarget = chunk.TargetContent || chunk.targetContent || '';
                            const rawReplacement = chunk.ReplacementContent || chunk.replacementContent || '';
                            const target = rawTarget.replace(/\r\n/g, '\n');
                            const replacement = rawReplacement.replace(/\r\n/g, '\n');
                            if (content.includes(target)) {
                                content = content.replace(target, replacement);
                            } else {
                                console.log(`[!] Multi-chunk target not found in ${filePath}`);
                            }
                        }
                        fs.writeFileSync(filePath, content);
                    }
                }
            }
        }
    }
}
console.log('Recovery complete!');
