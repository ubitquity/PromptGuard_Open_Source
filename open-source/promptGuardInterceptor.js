const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'secure.db'));

module.exports = function(req, res, next) {
    const systemPrompt = req.body.systemPrompt;
    if (!systemPrompt) return res.status(400).json({ error: "No system prompt provided." });

    const hash = crypto.createHash('sha256').update(systemPrompt).digest('hex');

    db.get("SELECT account FROM prompt_logs WHERE hash = ?", [hash], (err, row) => {
        if (err) return res.status(500).json({ error: "Internal security error." });

        if (!row) {
            console.warn(`🚨 BLOCKED: Unauthorized prompt. Hash: ${hash}`);
            return res.status(403).json({ error: "Security Violation: Prompt not notarized by ubitquity1." });
        }
        
        next(); // Authorization success
    });
};
