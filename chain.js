/**
 * ============================================================================
 * NULLNET CHAIN - MAIN BACKEND & WEBVIEW ENGINE (`chain.js`)
 * ============================================================================
 */

const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const { ethers } = require('ethers');
const nacl = require('tweetnacl');
const { Keypair } = require('@solana/web3.js');
const bs58 = require('bs58');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware configuration
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ============================================================================
// DATABASE INITIALIZATION & SEEDING
// ============================================================================
const db = new Database('./nullnet_chain.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    height INTEGER UNIQUE NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS wallets (
    address TEXT PRIMARY KEY,
    balance REAL NOT NULL DEFAULT 1000.0
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    block_id INTEGER,
    signature TEXT UNIQUE NOT NULL,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    amount REAL NOT NULL,
    type TEXT NOT NULL DEFAULT 'TRANSFER',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (block_id) REFERENCES blocks(id)
  );

  CREATE TABLE IF NOT EXISTS tokens (
    mint TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    symbol TEXT NOT NULL,
    total_supply REAL NOT NULL,
    owner TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS token_accounts (
    account_id INTEGER PRIMARY KEY AUTOINCREMENT,
    mint TEXT NOT NULL,
    owner TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0.0,
    UNIQUE(mint, owner),
    FOREIGN KEY (mint) REFERENCES tokens(mint)
  );

  CREATE TABLE IF NOT EXISTS program_state (
    program_id TEXT PRIMARY KEY,
    state_key TEXT NOT NULL,
    state_value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed Genesis Block if chain is empty
const blockCheck = db.prepare('SELECT COUNT(*) as count FROM blocks').get();
if (blockCheck.count === 0) {
  const genesisHash = crypto.createHash('sha256').update('NULLNET_GENESIS_BLOCK').digest('hex');
  db.prepare(`
    INSERT INTO blocks (height, prev_hash, hash) VALUES (?, ?, ?)
  `).run(0, '0x0000000000000000000000000000000000000000000000000000000000000000', genesisHash);
}

// ============================================================================
// CORE BLOCKCHAIN FUNCTIONS & HELPERS
// ============================================================================
function computeBlockHash(height, prevHash, timestamp) {
  return crypto.createHash('sha256').update(`${height}-${prevHash}-${timestamp}`).digest('hex');
}

function verifyWeb3Signature(message, signature, expectedAddress) {
  try {
    if (expectedAddress.startsWith('LUN')) {
      const rawPubkeyBase58 = expectedAddress.slice(3);
      const pubkeyBytes = bs58.decode(rawPubkeyBase58);
      const messageBytes = new TextEncoder().encode(message);
      const signatureBytes = bs58.decode(signature);
      return nacl.sign.detached.verify(messageBytes, signatureBytes, pubkeyBytes);
    } else {
      const recovered = ethers.verifyMessage(message, signature);
      return recovered.toLowerCase() === expectedAddress.toLowerCase();
    }
  } catch (err) {
    console.error('Signature verification exception:', err.message);
    return false;
  }
}

// ============================================================================
// API ENDPOINTS
// ============================================================================

app.get('/api/getBalance', (req, res) => {
  const { address } = req.query;
  if (!address) return res.status(400).json({ error: 'Missing address parameter' });

  let wallet = db.prepare('SELECT balance FROM wallets WHERE address = ?').get(address);
  if (!wallet) {
    db.prepare('INSERT INTO wallets (address, balance) VALUES (?, ?)').run(address, 100.0);
    wallet = { balance: 100.0 };
  }
  res.status(200).json({ address, balance: wallet.balance });
});

app.get('/api/getBlockHeight', (req, res) => {
  const result = db.prepare('SELECT MAX(height) as height FROM blocks').get();
  res.status(200).json({ height: result ? result.height : 0 });
});

app.get('/api/getRecentTransactions', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  try {
    const txs = db.prepare(`
      SELECT t.signature, t.sender, t.recipient, t.amount, t.type, t.timestamp, b.height as blockHeight
      FROM transactions t
      JOIN blocks b ON t.block_id = b.id
      ORDER BY t.id DESC
      LIMIT ?
    `).all(limit);
    res.status(200).json({ success: true, transactions: txs });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/getTokens', (req, res) => {
  const { owner } = req.query;
  try {
    const tokens = db.prepare(`
      SELECT t.mint, t.symbol, ta.balance as total_supply
      FROM token_accounts ta
      JOIN tokens t ON ta.mint = t.mint
      WHERE ta.owner = ? AND ta.balance > 0
    `).all(owner || '');
    res.status(200).json({ success: true, tokens });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/invokeSmartContract', (req, res) => {
  const { programId, action, symbol, supply, signer, signature } = req.body;
  if (!programId || !action || !signer) {
    return res.status(400).json({ error: 'Missing required contract parameters' });
  }

  try {
    if (signature) {
      const message = `Invoke ${programId}:${action} Symbol:${symbol} Supply:${supply}`;
      if (!verifyWeb3Signature(message, signature, signer)) {
        return res.status(401).json({ error: 'Invalid contract invocation signature' });
      }
    }

    if (action === 'deployToken') {
      const deployTokenTx = db.transaction(() => {
        db.prepare(`
          INSERT INTO tokens (mint, name, symbol, total_supply, owner)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(mint) DO UPDATE SET symbol = excluded.symbol, total_supply = excluded.total_supply, owner = excluded.owner
        `).run(programId, symbol, symbol, supply, signer);

        db.prepare(`
          INSERT INTO token_accounts (mint, owner, balance)
          VALUES (?, ?, ?)
          ON CONFLICT(mint, owner) DO UPDATE SET balance = excluded.balance
        `).run(programId, signer, supply);
      });
      deployTokenTx();
    }

    res.status(200).json({ success: true, message: `Program ${programId} executed action '${action}' successfully.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sendTransaction', (req, res) => {
  const { sender, recipient, amount, signature, asset } = req.body;
  if (!sender || !recipient || amount === undefined || !signature) {
    return res.status(400).json({ error: 'Missing required transaction fields or signature' });
  }

  try {
    const parsedAmount = parseFloat(amount);
    const messagePayload = `NullNet Transfer: Send ${parsedAmount} to ${recipient}`;
    
    if (!verifyWeb3Signature(messagePayload, signature, sender)) {
      return res.status(401).json({ error: 'Cryptographic signature verification failed.' });
    }

    const existingTx = db.prepare('SELECT id FROM transactions WHERE signature = ?').get(signature);
    if (existingTx) {
      return res.status(400).json({ error: 'Transaction signature already processed (Replay attack prevented).' });
    }

    const transferTx = db.transaction(() => {
      if (!asset || asset === 'LUN') {
        let senderW = db.prepare('SELECT balance FROM wallets WHERE address = ?').get(sender);
        if (!senderW || senderW.balance < parsedAmount) {
          throw new Error('Insufficient LUN balance in sender account.');
        }
        let recipientW = db.prepare('SELECT balance FROM wallets WHERE address = ?').get(recipient);
        if (!recipientW) {
          db.prepare('INSERT INTO wallets (address, balance) VALUES (?, ?)').run(recipient, 0.0);
        }
        db.prepare('UPDATE wallets SET balance = balance - ? WHERE address = ?').run(parsedAmount, sender);
        db.prepare('UPDATE wallets SET balance = balance + ? WHERE address = ?').run(parsedAmount, recipient);
      }

      const latestBlock = db.prepare('SELECT * FROM blocks ORDER BY height DESC LIMIT 1').get();
      const newHeight = latestBlock.height + 1;
      const timestamp = new Date().toISOString();
      const newHash = computeBlockHash(newHeight, latestBlock.hash, timestamp);

      const blockResult = db.prepare(`
        INSERT INTO blocks (height, prev_hash, hash, timestamp) VALUES (?, ?, ?, ?)
      `).run(newHeight, latestBlock.hash, newHash, timestamp);

      const blockId = blockResult.lastInsertRowid;

      db.prepare(`
        INSERT INTO transactions (block_id, signature, sender, recipient, amount, type, timestamp)
        VALUES (?, ?, ?, ?, ?, 'TRANSFER', ?)
      `).run(blockId, signature, sender, recipient, parsedAmount, timestamp);

      return { blockHeight: newHeight, blockHash: newHash, signature };
    });

    const result = transferTx();
    res.status(200).json({ success: true, ...result });

  } catch (err) {
    console.error('[Error] Transaction execution failed:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/faucet', (req, res) => {
  const { address, type } = req.body;
  try {
    let targetAddress = address;
    let walletDetails = {};
    const airdropAmount = 250.0;

    if (type === 'SOL' || type === 'LUN' || !address) {
      const solanaKeypair = Keypair.generate();
      const rawPubkey = solanaKeypair.publicKey.toBase58();
      targetAddress = `LUN${rawPubkey}`;
      
      walletDetails = {
        address: targetAddress,
        privateKey: bs58.encode(solanaKeypair.secretKey),
        type: 'LUN_SOLANA'
      };
    } else {
      walletDetails = { address: targetAddress, type: 'EVM' };
    }

    db.prepare(`
      INSERT INTO wallets (address, balance) VALUES (?, ?)
      ON CONFLICT(address) DO UPDATE SET balance = balance + ?
    `).run(targetAddress, airdropAmount, airdropAmount);

    res.status(200).json({
      success: true,
      message: `Successfully airdropped ${airdropAmount} COIN to ${targetAddress}.`,
      wallet: walletDetails
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// BACKGROUND BLOCK PRODUCTION ENGINE (MINER / HEARTBEAT)
// ============================================================================
const BLOCK_INTERVAL_MS = 15000; // Mints an automated block every 15 seconds

const produceBackgroundBlock = db.transaction(() => {
  const latestBlock = db.prepare('SELECT * FROM blocks ORDER BY height DESC LIMIT 1').get();
  const newHeight = latestBlock.height + 1;
  const timestamp = new Date().toISOString();
  const newHash = computeBlockHash(newHeight, latestBlock.hash, timestamp);

  db.prepare(`
    INSERT INTO blocks (height, prev_hash, hash, timestamp) VALUES (?, ?, ?, ?)
  `).run(newHeight, latestBlock.hash, newHash, timestamp);

  return { height: newHeight, hash: newHash };
});

setInterval(() => {
  try {
    const result = produceBackgroundBlock();
    console.log(`[NullNet Miner] Successfully mined block #${result.height} | Hash: ${result.hash.substring(0, 12)}...`);
  } catch (err) {
    console.error('[NullNet Miner Error]:', err.message);
  }
}, BLOCK_INTERVAL_MS);

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'online', network: 'NullNet Chain Backend is live.' });
});

app.listen(PORT, () => {
  console.log(`[NullNet Node] Chain backend running on port ${PORT}`);
});