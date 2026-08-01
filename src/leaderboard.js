import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_FILE = path.join(__dirname, 'database.json');

// In-memory cache to prevent race conditions (C-02) and avoid sync I/O (C-01, P-01)
let dbCache = null;
let writeTimer = null;
const WRITE_DEBOUNCE_MS = 500;

function ensureCache() {
  if (dbCache === null) {
    try {
      if (fs.existsSync(DB_FILE)) {
        dbCache = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
      } else {
        dbCache = { leaderboard: {} };
      }
    } catch (err) {
      console.error('[Leaderboard] Failed to read database:', err.message);
      dbCache = { leaderboard: {} };
    }
  }
  return dbCache;
}

function scheduleWrite() {
  // Debounce writes to prevent 30 synchronous writes during batch scans (P-01)
  if (writeTimer) clearTimeout(writeTimer);
  writeTimer = setTimeout(() => {
    try {
      const data = JSON.stringify(dbCache, null, 2);
      fs.writeFile(DB_FILE, data, 'utf-8', (err) => {
        if (err) console.error('[Leaderboard] Failed to write database:', err.message);
      });
    } catch (err) {
      console.error('[Leaderboard] Failed to serialize database:', err.message);
    }
  }, WRITE_DEBOUNCE_MS);
}

export function saveResult(hostname, data) {
  const db = ensureCache();
  db.leaderboard[hostname] = data;
  scheduleWrite();
}

export function getLeaderboard() {
  const db = ensureCache();
  return Object.values(db.leaderboard || {}).sort((a, b) => (b.score || 0) - (a.score || 0));
}
