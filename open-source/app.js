const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(express.static(__dirname));

// Initialize SQLite database for local audit logs
const db = new sqlite3.Database(path.join(__dirname, 'secure.db'));
db.run(`CREATE TABLE IF NOT EXISTS prompt_logs (
    id INTEGER PRIMARY KEY, 
    account TEXT, 
    hash TEXT, 
    txid TEXT, 
    token_used TEXT, 
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Serve the admin dashboard
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Blockchain verification logic
async function verifyWebAuthTransaction(txid, expectedHash, expectedAccount, expectedToken) {
    try {
        const response = await fetch('https://proton.cryptolions.io/v1/history/get_transaction', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: txid })
        });
        
        if (!response.ok) return false;
        const txData = await response.json();
        
        // Strictly verify: contract=tokencreate, sender=ubitquity1, quantity=1.00000000
        const expectedQuantity = `1.00000000 ${expectedToken}`;
        const action = txData.trx.trx.actions.find(a => 
            a.account === 'tokencreate' &&
            a.name === 'transfer' &&
            a.data.from === expectedAccount &&
            a.data.quantity === expectedQuantity
        );

        if (!action) return false;

        const expectedMemo = `REPORT:${expectedHash}:CLEAN_PROMPT`;
        return action.data.memo === expectedMemo;
    } catch (error) {
        return false;
    }
}

// Verification Endpoint - Hardcoded for ubitquity1
app.post('/api/verify', async (req, res) => {
    const { account, hash, txid, token } = req.body;
    
    if (!account || !hash || !txid || !token) {
        return res.status(400).json({ success: false, error: "Missing required fields: account, hash, txid, token." });
    }

    if (account !== 'ubitquity1') {
        return res.status(403).json({ success: false, error: "Unauthorized WebAuth account. ubitquity1 required." });
    }

    const isValidOnChain = await verifyWebAuthTransaction(txid, hash, account, token);
    if (!isValidOnChain) {
        return res.status(403).json({ success: false, error: "Blockchain verification failed." });
    }
    
    const stmt = db.prepare("INSERT INTO prompt_logs (account, hash, txid, token_used) VALUES (?, ?, ?, ?)");
    stmt.run(account, hash, txid, token, (err) => {
        stmt.finalize();
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, message: "Prompt audited for ubitquity1." });
    });
});

// Health check for dashboard
app.get('/api/health', async (req, res) => {
    db.get("SELECT COUNT(*) as count FROM prompt_logs", (err, row) => {
        res.json({ status: err ? 'unhealthy' : 'healthy', prompts: row ? row.count : 0 });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT);
