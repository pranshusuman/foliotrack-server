// FolioTrack — Secure Backend
// Handles: auth, portfolio storage, live prices, AI news, daily email digest
// Deploy on Railway (free) — see DEPLOY_GUIDE.md

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const { createClient } = require('@supabase/supabase-js');
const Anthropic = require('@anthropic-ai/sdk');
require('dotenv').config();

const app = express();
app.use(cors({ origin: process.env.CLIENT_URL || '*' }));
app.use(express.json({ limit: '20mb' }));

// ── Clients ────────────────────────────────────────────────────────────────
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── Email via Resend API (works reliably on Railway) ──────────────────────
async function sendEmail({ to, subject, html }) {
  if (!process.env.RESEND_API_KEY) {
    console.error('❌ RESEND_API_KEY not set');
    throw new Error('Email not configured');
  }
  const from = process.env.EMAIL_FROM || 'FolioTrack <onboarding@resend.dev>';
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + process.env.RESEND_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from, to, subject, html })
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error('Resend API error: ' + err);
  }
  return resp.json();
}

console.log('✅ Email configured via Resend');

// ── Auth middleware ────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired — please log in again' });
  }
}

// ── Health check ───────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ══════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════

// Sign up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });

    // Check existing
    const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).single();
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const { data: user, error } = await supabase.from('users')
      .insert({ name, email: email.toLowerCase(), password: hashed, notify_email: true })
      .select().single();
    if (error) throw error;

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) {
    console.error('Signup error:', e);
    res.status(500).json({ error: 'Signup failed. Please try again.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('email', email.toLowerCase()).single();
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
  const { data: user } = await supabase.from('users').select('id,name,email,notify_email').eq('id', req.user.id).single();
  res.json(user);
});

// ══════════════════════════════════════════════════════════════════════════
// PORTFOLIO ROUTES
// ══════════════════════════════════════════════════════════════════════════

// Get portfolio + transactions
app.get('/api/portfolio', auth, async (req, res) => {
  try {
    // Fetch holdings (usually small, no limit needed)
    const { data: portfolio } = await supabase
      .from('holdings').select('*').eq('user_id', req.user.id);

    // Fetch ALL transactions — Supabase default limit is 1000, must paginate
    let transactions = [];
    let from = 0;
    const pageSize = 1000;
    while (true) {
      const { data, error } = await supabase
        .from('transactions').select('*')
        .eq('user_id', req.user.id)
        .order('date', { ascending: true })
        .range(from, from + pageSize - 1);
      if (error) throw error;
      if (!data || data.length === 0) break;
      transactions = transactions.concat(data);
      if (data.length < pageSize) break; // Last page
      from += pageSize;
    }

    res.json({ portfolio: portfolio || [], transactions });
  } catch (e) {
    console.error('Portfolio fetch error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Add transaction (buy or sell)
app.post('/api/portfolio/transaction', auth, async (req, res) => {
  try {
    const { ticker, exchange, qty, price, date, type, broker } = req.body;
    const brokerName = (broker || 'Main').trim();
    if (!ticker || !qty || !price || !date || !type) return res.status(400).json({ error: 'All fields required' });
    if (!price || price <= 0) return res.status(400).json({ error: 'Buy price is required — never assumed' });

    // Save transaction
    const { data: tx, error: txErr } = await supabase.from('transactions').insert({
      user_id: req.user.id, ticker: ticker.toUpperCase(), exchange, qty, price, date, type, broker: brokerName
    }).select().single();
    if (txErr) throw txErr;

    // Update holdings (keyed by broker too)
    if (type === 'buy') {
      const { data: existing } = await supabase.from('holdings')
        .select('*').eq('user_id', req.user.id).eq('ticker', ticker.toUpperCase())
        .eq('exchange', exchange).eq('broker', brokerName).single();

      if (existing) {
        const newQty = existing.qty + qty;
        const newAvg = (existing.avg_cost * existing.qty + price * qty) / newQty;
        await supabase.from('holdings').update({ qty: newQty, avg_cost: newAvg }).eq('id', existing.id);
      } else {
        await supabase.from('holdings').insert({
          user_id: req.user.id, ticker: ticker.toUpperCase(), exchange,
          qty, avg_cost: price, buy_date: date, broker: brokerName
        });
      }
    } else if (type === 'sell') {
      const { data: existing } = await supabase.from('holdings')
        .select('*').eq('user_id', req.user.id).eq('ticker', ticker.toUpperCase())
        .eq('exchange', exchange).eq('broker', brokerName).single();
      if (existing) {
        const newQty = existing.qty - qty;
        if (newQty <= 0) await supabase.from('holdings').delete().eq('id', existing.id);
        else await supabase.from('holdings').update({ qty: newQty }).eq('id', existing.id);
      }
    }

    res.json({ success: true, transaction: tx });
  } catch (e) {
    console.error('Transaction error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Delete transaction + auto-recalculate holdings
app.delete('/api/portfolio/transaction/:id', auth, async (req, res) => {
  try {
    const { data: tx } = await supabase.from('transactions')
      .select('*').eq('id', req.params.id).eq('user_id', req.user.id).single();
    if (!tx) return res.status(404).json({ error: 'Transaction not found' });

    await supabase.from('transactions').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    await rebuildHoldingForStock(req.user.id, tx.ticker, tx.exchange, tx.broker || 'Main');
    res.json({ success: true });
  } catch (e) {
    console.error('Delete tx error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Edit transaction + auto-recalculate holdings
app.patch('/api/portfolio/transaction/:id', auth, async (req, res) => {
  try {
    const { ticker, exchange, qty, price, date, type, broker } = req.body;

    // Get original to know old stock grouping (in case ticker/broker changed)
    const { data: original } = await supabase.from('transactions')
      .select('*').eq('id', req.params.id).eq('user_id', req.user.id).single();
    if (!original) return res.status(404).json({ error: 'Transaction not found' });

    const updates = {};
    if (ticker !== undefined) updates.ticker = String(ticker).toUpperCase();
    if (exchange !== undefined) updates.exchange = exchange;
    if (qty !== undefined) updates.qty = Number(qty);
    if (price !== undefined) updates.price = Number(price);
    if (date !== undefined) updates.date = date;
    if (type !== undefined) updates.type = type;
    if (broker !== undefined) updates.broker = String(broker).trim();

    const { error } = await supabase.from('transactions')
      .update(updates).eq('id', req.params.id).eq('user_id', req.user.id);
    if (error) throw error;

    // Rebuild old stock grouping (if ticker/exchange/broker changed)
    await rebuildHoldingForStock(req.user.id, original.ticker, original.exchange, original.broker || 'Main');

    // Also rebuild new grouping if different
    const newTicker = updates.ticker || original.ticker;
    const newExchange = updates.exchange || original.exchange;
    const newBroker = updates.broker || original.broker || 'Main';
    if (newTicker !== original.ticker || newExchange !== original.exchange || newBroker !== (original.broker || 'Main')) {
      await rebuildHoldingForStock(req.user.id, newTicker, newExchange, newBroker);
    }

    res.json({ success: true });
  } catch (e) {
    console.error('Edit tx error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Helper: rebuild a single holding from its transactions
async function rebuildHoldingForStock(userId, ticker, exchange, broker) {
  let remaining = [];
  let remFrom = 0;
  while (true) {
    const { data } = await supabase.from('transactions')
      .select('type, qty, price, date')
      .eq('user_id', userId).eq('ticker', ticker)
      .eq('exchange', exchange).eq('broker', broker)
      .order('date', { ascending: true })
      .range(remFrom, remFrom + 999);
    if (!data || data.length === 0) break;
    remaining = remaining.concat(data);
    if (data.length < 1000) break;
    remFrom += 1000;
  }

  let netQty = 0, totalCost = 0, totalBuyQty = 0, firstBuyDate = null;
  remaining.forEach(t => {
    const q = Number(t.qty), p = Number(t.price);
    if (t.type === 'buy') {
      netQty += q; totalCost += q * p; totalBuyQty += q;
      if (!firstBuyDate) firstBuyDate = t.date;
    } else {
      netQty -= q;
    }
  });
  const avgCost = totalBuyQty > 0 ? totalCost / totalBuyQty : 0;

  // Delete existing then insert if needed (avoids race conditions)
  await supabase.from('holdings').delete()
    .eq('user_id', userId).eq('ticker', ticker)
    .eq('exchange', exchange).eq('broker', broker);

  if (netQty > 0.001 && avgCost > 0) {
    await supabase.from('holdings').insert({
      user_id: userId, ticker, exchange, broker,
      qty: Math.round(netQty * 1000) / 1000,
      avg_cost: Math.round(avgCost * 100) / 100,
      buy_date: firstBuyDate || new Date().toISOString().split('T')[0]
    });
  }
}

// Edit a holding (update qty, avg cost, or buy date)
app.patch('/api/portfolio/holding/:id', auth, async (req, res) => {
  try {
    const { qty, avg_cost, buy_date } = req.body;
    const updates = {};
    if (qty !== undefined) updates.qty = qty;
    if (avg_cost !== undefined) updates.avg_cost = avg_cost;
    if (buy_date !== undefined) updates.buy_date = buy_date;
    const { data, error } = await supabase.from('holdings')
      .update(updates).eq('id', req.params.id).eq('user_id', req.user.id).select().single();
    if (error) throw error;
    res.json({ success: true, holding: data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Delete a holding entirely (also removes related transactions)
app.delete('/api/portfolio/holding/:id', auth, async (req, res) => {
  try {
    const { data: holding } = await supabase.from('holdings')
      .select('*').eq('id', req.params.id).eq('user_id', req.user.id).single();
    if (!holding) return res.status(404).json({ error: 'Holding not found' });
    // Delete related transactions
    await supabase.from('transactions').delete()
      .eq('user_id', req.user.id).eq('ticker', holding.ticker).eq('exchange', holding.exchange);
    // Delete the holding
    await supabase.from('holdings').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Bulk import (from file upload parsing)
app.post('/api/portfolio/import', auth, async (req, res) => {
  try {
    const { holdings, broker } = req.body;
    const brokerName = (broker || 'Main').trim();
    const missing = [];
    for (const h of holdings) {
      if (!h.ticker) continue;
      if (!h.avgCost || h.avgCost <= 0) { missing.push(h.ticker.toUpperCase()); continue; }
      const { data: existing } = await supabase.from('holdings')
        .select('*').eq('user_id', req.user.id).eq('ticker', h.ticker.toUpperCase())
        .eq('broker', brokerName).single();
      if (!existing) {
        await supabase.from('holdings').insert({
          user_id: req.user.id, ticker: h.ticker.toUpperCase(),
          exchange: h.exchange || 'NSE', qty: h.qty || 0,
          avg_cost: h.avgCost, buy_date: h.buyDate || new Date().toISOString().split('T')[0],
          broker: brokerName
        });
      }
    }
    res.json({ success: true, imported: holdings.length, missingPrices: missing });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// REBUILD ALL HOLDINGS from scratch based on ALL transactions
// Use this when holdings are out of sync with transactions
app.post('/api/portfolio/rebuild', auth, async (req, res) => {
  try {
    console.log(`🔨 Rebuilding all holdings for user ${req.user.id}...`);

    // Step 1: Fetch ALL transactions (paginated)
    let allTxs = [];
    let from = 0;
    while (true) {
      const { data, error } = await supabase
        .from('transactions').select('*')
        .eq('user_id', req.user.id)
        .order('date', { ascending: true })
        .range(from, from + 999);
      if (error) throw error;
      if (!data || data.length === 0) break;
      allTxs = allTxs.concat(data);
      if (data.length < 1000) break;
      from += 1000;
    }

    console.log(`Found ${allTxs.length} transactions to process`);

    // Step 2: Group by ticker+exchange+broker
    const groups = {};
    allTxs.forEach(t => {
      const key = `${t.ticker}|${t.exchange}|${t.broker || 'Main'}`;
      if (!groups[key]) groups[key] = [];
      groups[key].push(t);
    });

    // Step 3: Delete ALL existing holdings
    await supabase.from('holdings').delete().eq('user_id', req.user.id);

    // Step 4: Recompute and insert fresh holdings
    let rebuilt = 0, closed = 0;
    const newHoldings = [];

    for (const [key, txs] of Object.entries(groups)) {
      const [ticker, exchange, broker] = key.split('|');
      let netQty = 0, totalBuyCost = 0, totalBuyQty = 0, firstBuyDate = null;

      txs.forEach(t => {
        const q = Number(t.qty), p = Number(t.price);
        if (t.type === 'buy') {
          netQty += q;
          totalBuyCost += q * p;
          totalBuyQty += q;
          if (!firstBuyDate) firstBuyDate = t.date;
        } else {
          netQty -= q;
        }
      });

      const avgCost = totalBuyQty > 0 ? totalBuyCost / totalBuyQty : 0;

      if (netQty > 0.001 && avgCost > 0) {
        newHoldings.push({
          user_id: req.user.id,
          ticker, exchange, broker,
          qty: Math.round(netQty * 1000) / 1000,
          avg_cost: Math.round(avgCost * 100) / 100,
          buy_date: firstBuyDate || new Date().toISOString().split('T')[0]
        });
        rebuilt++;
      } else {
        closed++;
      }
    }

    // Bulk insert all new holdings
    if (newHoldings.length > 0) {
      const chunkSize = 500;
      for (let i = 0; i < newHoldings.length; i += chunkSize) {
        const { error } = await supabase.from('holdings').insert(newHoldings.slice(i, i + chunkSize));
        if (error) throw error;
      }
    }

    console.log(`✅ Rebuilt ${rebuilt} holdings, ${closed} fully closed positions`);
    res.json({ success: true, rebuilt, closed, total: allTxs.length });

  } catch (e) {
    console.error('Rebuild error:', e);
    res.status(500).json({ error: e.message });
  }
});
// Fixed: sequential holding rebuild to avoid race conditions
app.post('/api/portfolio/transactions/bulk', auth, async (req, res) => {
  try {
    const { transactions: incoming } = req.body;
    if (!Array.isArray(incoming) || !incoming.length) return res.status(400).json({ error: 'No transactions' });

    // Prepare rows
    const rows = incoming.map(tx => ({
      user_id: req.user.id,
      ticker: String(tx.ticker || '').toUpperCase(),
      exchange: tx.exchange || 'NSE',
      qty: Number(tx.qty),
      price: Number(tx.price),
      date: tx.date,
      type: tx.type,
      broker: (tx.broker || 'Main').trim()
    })).filter(r => r.ticker && r.qty > 0 && r.price > 0 && r.date && (r.type === 'buy' || r.type === 'sell'));

    if (!rows.length) return res.status(400).json({ error: 'No valid transactions' });

    // Chunk transactions insert (Supabase limit ~1000/call)
    let insertedCount = 0;
    for (let i = 0; i < rows.length; i += 500) {
      const chunk = rows.slice(i, i + 500);
      const { data: inserted, error: insErr } = await supabase.from('transactions').insert(chunk).select('id');
      if (insErr) throw insErr;
      insertedCount += (inserted || []).length;
    }

    // Collect unique holdings to rebuild
    const affected = new Set();
    rows.forEach(r => affected.add(`${r.ticker}|${r.exchange}|${r.broker}`));

    // Rebuild holdings SEQUENTIALLY to prevent race conditions
    let holdingsRebuilt = 0, holdingsDeleted = 0, errors = [];
    for (const key of affected) {
      try {
        const [ticker, exchange, broker] = key.split('|');

        // Fetch ALL transactions for this stock (paginated)
        let allTxs = [];
        let txFrom = 0;
        while (true) {
          const { data, error: txErr } = await supabase.from('transactions')
            .select('type, qty, price, date')
            .eq('user_id', req.user.id)
            .eq('ticker', ticker)
            .eq('exchange', exchange)
            .eq('broker', broker)
            .order('date', { ascending: true })
            .range(txFrom, txFrom + 999);
          if (txErr) throw txErr;
          if (!data || data.length === 0) break;
          allTxs = allTxs.concat(data);
          if (data.length < 1000) break;
          txFrom += 1000;
        }

        // Calculate current net position
        let netQty = 0, totalBuyCost = 0, totalBuyQty = 0, firstBuyDate = null;
        (allTxs || []).forEach(t => {
          const q = Number(t.qty), p = Number(t.price);
          if (t.type === 'buy') {
            netQty += q;
            totalBuyCost += q * p;
            totalBuyQty += q;
            if (!firstBuyDate) firstBuyDate = t.date;
          } else {
            netQty -= q;
          }
        });
        const avgCost = totalBuyQty > 0 ? totalBuyCost / totalBuyQty : 0;

        // Delete existing holding first (avoids duplicate key conflict)
        await supabase.from('holdings')
          .delete()
          .eq('user_id', req.user.id)
          .eq('ticker', ticker)
          .eq('exchange', exchange)
          .eq('broker', broker);

        // Insert fresh holding if still positive
        if (netQty > 0 && avgCost > 0) {
          const { error: hErr } = await supabase.from('holdings').insert({
            user_id: req.user.id,
            ticker, exchange, broker,
            qty: netQty,
            avg_cost: avgCost,
            buy_date: firstBuyDate || new Date().toISOString().split('T')[0]
          });
          if (hErr) throw hErr;
          holdingsRebuilt++;
        } else {
          holdingsDeleted++;
        }
      } catch (err) {
        errors.push(`${key}: ${err.message}`);
        console.error(`Failed to rebuild ${key}:`, err.message);
      }
    }

    res.json({
      success: true,
      imported: insertedCount,
      holdingsRebuilt,
      holdingsDeleted,
      errors: errors.slice(0, 10)
    });
  } catch (e) {
    console.error('Bulk import error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Get list of brokers with STATS + HOLDER name (Stage 2)
app.get('/api/brokers', auth, async (req, res) => {
  try {
    // Fetch all holdings paginated
    let allHoldings = [];
    let hFrom = 0;
    while (true) {
      const { data } = await supabase.from('holdings').select('*')
        .eq('user_id', req.user.id).range(hFrom, hFrom + 999);
      if (!data || data.length === 0) break;
      allHoldings = allHoldings.concat(data);
      if (data.length < 1000) break;
      hFrom += 1000;
    }

    // Fetch all transactions paginated
    let allTx = [];
    let txFrom = 0;
    while (true) {
      const { data } = await supabase.from('transactions').select('*')
        .eq('user_id', req.user.id).range(txFrom, txFrom + 999);
      if (!data || data.length === 0) break;
      allTx = allTx.concat(data);
      if (data.length < 1000) break;
      txFrom += 1000;
    }

    // Fetch holder metadata (may not exist if broker_meta table not created yet)
    let holderMap = {};
    try {
      const { data: meta } = await supabase.from('broker_meta').select('*').eq('user_id', req.user.id);
      (meta || []).forEach(m => { holderMap[m.broker] = m.holder; });
    } catch {}

    // Build broker stats
    const brokerNames = new Set();
    allHoldings.forEach(h => brokerNames.add(h.broker || 'Main'));
    allTx.forEach(t => brokerNames.add(t.broker || 'Main'));

    const brokers = [];
    for (const name of brokerNames) {
      const holdings = allHoldings.filter(h => (h.broker || 'Main') === name);
      const txs = allTx.filter(t => (t.broker || 'Main') === name);
      const invested = txs.filter(t => t.type === 'buy').reduce((s, t) => s + Number(t.qty) * Number(t.price), 0);
      const sold = txs.filter(t => t.type === 'sell').reduce((s, t) => s + Number(t.qty) * Number(t.price), 0);
      const dates = txs.map(t => t.date).filter(Boolean).sort();
      brokers.push({
        name,
        holder: holderMap[name] || '',
        holdingsCount: holdings.length,
        transactionsCount: txs.length,
        invested: Math.round(invested),
        sold: Math.round(sold),
        firstDate: dates[0] || null,
        lastDate: dates[dates.length - 1] || null
      });
    }

    if (!brokers.length) brokers.push({
      name: 'Main', holder: '', holdingsCount: 0, transactionsCount: 0,
      invested: 0, sold: 0, firstDate: null, lastDate: null
    });

    res.json({ brokers });
  } catch (e) {
    console.error('Brokers fetch error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Rename a broker across all holdings & transactions
app.post('/api/brokers/rename', auth, async (req, res) => {
  try {
    const { oldName, newName } = req.body;
    if (!oldName || !newName) return res.status(400).json({ error: 'Both names required' });
    await supabase.from('holdings').update({ broker: newName }).eq('user_id', req.user.id).eq('broker', oldName);
    await supabase.from('transactions').update({ broker: newName }).eq('user_id', req.user.id).eq('broker', oldName);
    // Migrate holder meta too
    try {
      await supabase.from('broker_meta').update({ broker: newName }).eq('user_id', req.user.id).eq('broker', oldName);
    } catch {}
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// MERGE brokers — transfer transactions from source to target and rebuild holdings
app.post('/api/brokers/merge', auth, async (req, res) => {
  try {
    const { source, target } = req.body;
    if (!source || !target) return res.status(400).json({ error: 'Source and target required' });
    if (source === target) return res.status(400).json({ error: 'Source and target must differ' });

    // Move transactions from source → target (chunked)
    let moved = 0;
    while (true) {
      const { data: batch } = await supabase.from('transactions')
        .select('id').eq('user_id', req.user.id).eq('broker', source).limit(1000);
      if (!batch || batch.length === 0) break;
      await supabase.from('transactions').update({ broker: target }).in('id', batch.map(t => t.id));
      moved += batch.length;
      if (batch.length < 1000) break;
    }

    // Delete old holdings for both
    await supabase.from('holdings').delete().eq('user_id', req.user.id).in('broker', [source, target]);

    // Fetch target transactions (paginated) and rebuild
    let allTx = [];
    let from = 0;
    while (true) {
      const { data } = await supabase.from('transactions')
        .select('*').eq('user_id', req.user.id).eq('broker', target)
        .order('date', { ascending: true }).range(from, from + 999);
      if (!data || data.length === 0) break;
      allTx = allTx.concat(data);
      if (data.length < 1000) break;
      from += 1000;
    }

    const groups = {};
    allTx.forEach(t => {
      const key = `${t.ticker}|${t.exchange}`;
      if (!groups[key]) groups[key] = [];
      groups[key].push(t);
    });

    const newHoldings = [];
    for (const [key, txs] of Object.entries(groups)) {
      const [ticker, exchange] = key.split('|');
      let netQty = 0, totalCost = 0, totalBuyQty = 0, firstBuyDate = null;
      txs.forEach(t => {
        const q = Number(t.qty), p = Number(t.price);
        if (t.type === 'buy') { netQty += q; totalCost += q * p; totalBuyQty += q; if (!firstBuyDate) firstBuyDate = t.date; }
        else netQty -= q;
      });
      const avgCost = totalBuyQty > 0 ? totalCost / totalBuyQty : 0;
      if (netQty > 0.001 && avgCost > 0) {
        newHoldings.push({
          user_id: req.user.id, ticker, exchange, broker: target,
          qty: Math.round(netQty * 1000) / 1000,
          avg_cost: Math.round(avgCost * 100) / 100,
          buy_date: firstBuyDate || new Date().toISOString().split('T')[0]
        });
      }
    }

    if (newHoldings.length) {
      for (let i = 0; i < newHoldings.length; i += 500) {
        await supabase.from('holdings').insert(newHoldings.slice(i, i + 500));
      }
    }

    res.json({ success: true, transactionsMoved: moved, holdingsRebuilt: newHoldings.length });
  } catch (e) {
    console.error('Merge broker error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Set holder name for a broker (Stage 2)
app.patch('/api/brokers/holder', auth, async (req, res) => {
  try {
    const { broker, holder } = req.body;
    if (!broker) return res.status(400).json({ error: 'Broker required' });
    try {
      await supabase.from('broker_meta').upsert({
        user_id: req.user.id, broker, holder: holder || ''
      }, { onConflict: 'user_id,broker' });
      res.json({ success: true });
    } catch(e) {
      // Table may not exist — return friendly error
      res.status(500).json({ error: 'broker_meta table not created. Run migration v3 SQL first.' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Delete all data for a specific broker
app.delete('/api/brokers/:name', auth, async (req, res) => {
  try {
    const name = req.params.name;
    if (!name) return res.status(400).json({ error: 'Broker name required' });

    let totalTx = 0;
    while (true) {
      const { data: toDelete } = await supabase.from('transactions')
        .select('id').eq('user_id', req.user.id).eq('broker', name).limit(1000);
      if (!toDelete || toDelete.length === 0) break;
      const ids = toDelete.map(t => t.id);
      await supabase.from('transactions').delete().in('id', ids);
      totalTx += toDelete.length;
      if (toDelete.length < 1000) break;
    }

    const { data: holdings } = await supabase.from('holdings')
      .select('id').eq('user_id', req.user.id).eq('broker', name);
    const totalH = (holdings || []).length;
    if (totalH > 0) {
      await supabase.from('holdings').delete().in('id', holdings.map(h => h.id));
    }

    // Delete holder meta too
    try {
      await supabase.from('broker_meta').delete().eq('user_id', req.user.id).eq('broker', name);
    } catch {}

    res.json({ success: true, transactionsDeleted: totalTx, holdingsDeleted: totalH });
  } catch (e) {
    console.error('Delete broker error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Server-side XIRR (Stage 2) — for large datasets where client-side is slow
function xirrNewton(values, dates, guess = 0.1) {
  if (!values || !dates || values.length !== dates.length || values.length < 2) return null;
  const d0 = new Date(dates[0]);
  const years = dates.map(d => (new Date(d) - d0) / (365.25 * 24 * 3600 * 1000));
  let r = guess;
  for (let iter = 0; iter < 100; iter++) {
    let npv = 0, dnpv = 0;
    for (let i = 0; i < values.length; i++) {
      const base = Math.pow(1 + r, years[i]);
      if (!isFinite(base) || base === 0) return null;
      npv += values[i] / base;
      dnpv += -years[i] * values[i] / (base * (1 + r));
    }
    if (!isFinite(dnpv) || Math.abs(dnpv) < 1e-10) break;
    const newR = r - npv / dnpv;
    if (!isFinite(newR)) return null;
    if (Math.abs(newR - r) < 1e-6) return newR;
    r = newR;
  }
  return r;
}

app.post('/api/xirr', auth, async (req, res) => {
  try {
    const { tickers, livePrices } = req.body;
    // livePrices: {TICKER: ltp, ...} — client passes current prices

    // Fetch all transactions (paginated)
    let allTx = [];
    let from = 0;
    while (true) {
      const { data } = await supabase.from('transactions').select('*')
        .eq('user_id', req.user.id).order('date', { ascending: true }).range(from, from + 999);
      if (!data || data.length === 0) break;
      allTx = allTx.concat(data);
      if (data.length < 1000) break;
      from += 1000;
    }

    // Fetch holdings
    const { data: holdings } = await supabase.from('holdings').select('*').eq('user_id', req.user.id);
    const holdMap = {};
    (holdings || []).forEach(h => { holdMap[h.ticker] = h; });

    const today = new Date().toISOString().split('T')[0];
    const result = { portfolio: null, stocks: {} };

    // Portfolio XIRR
    const pVals = [], pDates = [];
    allTx.forEach(t => {
      pVals.push(t.type === 'buy' ? -(t.qty * t.price) : t.qty * t.price);
      pDates.push(t.date);
    });
    let termVal = 0;
    (holdings || []).forEach(h => {
      const ltp = (livePrices && livePrices[h.ticker]) || h.avg_cost;
      termVal += h.qty * ltp;
    });
    if (termVal > 0) { pVals.push(termVal); pDates.push(today); }
    if (pVals.some(v => v < 0) && pVals.some(v => v > 0)) {
      const x = xirrNewton(pVals, pDates);
      if (x !== null && isFinite(x) && x > -0.99 && x < 10) result.portfolio = x * 100;
    }

    // Stock-wise XIRR (only for held stocks, if tickers filter given)
    const stocksToCompute = tickers || Object.keys(holdMap);
    const byTicker = {};
    allTx.forEach(t => {
      if (!byTicker[t.ticker]) byTicker[t.ticker] = [];
      byTicker[t.ticker].push(t);
    });

    for (const tk of stocksToCompute) {
      const txs = byTicker[tk] || [];
      if (!txs.length || !holdMap[tk]) continue;
      const vals = txs.map(t => t.type === 'buy' ? -(t.qty * t.price) : t.qty * t.price);
      const dates = txs.map(t => t.date);
      const ltp = (livePrices && livePrices[tk]) || holdMap[tk].avg_cost;
      vals.push(holdMap[tk].qty * ltp);
      dates.push(today);
      if (vals.some(v => v < 0) && vals.some(v => v > 0)) {
        const x = xirrNewton(vals, dates);
        if (x !== null && isFinite(x) && x > -0.99 && x < 10) result.stocks[tk] = x * 100;
      }
    }

    res.json(result);
  } catch (e) {
    console.error('XIRR error:', e);
    res.status(500).json({ error: e.message });
  }
});

// SCOPED rebuild — all / broker / stock (Stage 2)
app.post('/api/portfolio/rebuild-scoped', auth, async (req, res) => {
  try {
    const { scope, broker, ticker } = req.body;

    let query = supabase.from('transactions').select('*').eq('user_id', req.user.id);
    if (scope === 'broker' && broker) query = query.eq('broker', broker);
    else if (scope === 'stock' && ticker) query = query.eq('ticker', ticker);

    let allTx = [];
    let from = 0;
    while (true) {
      const { data } = await query.order('date', { ascending: true }).range(from, from + 999);
      if (!data || data.length === 0) break;
      allTx = allTx.concat(data);
      if (data.length < 1000) break;
      from += 1000;
    }

    // Delete existing holdings for same scope
    let delQuery = supabase.from('holdings').delete().eq('user_id', req.user.id);
    if (scope === 'broker' && broker) delQuery = delQuery.eq('broker', broker);
    else if (scope === 'stock' && ticker) delQuery = delQuery.eq('ticker', ticker);
    await delQuery;

    const groups = {};
    allTx.forEach(t => {
      const key = `${t.ticker}|${t.exchange}|${t.broker || 'Main'}`;
      if (!groups[key]) groups[key] = [];
      groups[key].push(t);
    });

    const newHoldings = [];
    for (const [key, txs] of Object.entries(groups)) {
      const [tk, ex, br] = key.split('|');
      let netQty = 0, totalCost = 0, totalBuyQty = 0, firstBuyDate = null;
      txs.forEach(t => {
        const q = Number(t.qty), p = Number(t.price);
        if (t.type === 'buy') { netQty += q; totalCost += q * p; totalBuyQty += q; if (!firstBuyDate) firstBuyDate = t.date; }
        else netQty -= q;
      });
      const avgCost = totalBuyQty > 0 ? totalCost / totalBuyQty : 0;
      if (netQty > 0.001 && avgCost > 0) {
        newHoldings.push({
          user_id: req.user.id, ticker: tk, exchange: ex, broker: br,
          qty: Math.round(netQty * 1000) / 1000,
          avg_cost: Math.round(avgCost * 100) / 100,
          buy_date: firstBuyDate || new Date().toISOString().split('T')[0]
        });
      }
    }

    if (newHoldings.length) {
      for (let i = 0; i < newHoldings.length; i += 500) {
        await supabase.from('holdings').insert(newHoldings.slice(i, i + 500));
      }
    }

    res.json({ success: true, rebuilt: newHoldings.length, transactionsProcessed: allTx.length });
  } catch (e) {
    console.error('Rebuild scoped error:', e);
    res.status(500).json({ error: e.message });
  }
});

// TICKER CACHE endpoints (Stage 2)
app.get('/api/ticker-cache', auth, async (req, res) => {
  try {
    let allRows = [];
    let from = 0;
    while (true) {
      const { data, error } = await supabase.from('ticker_cache')
        .select('company_name, ticker').range(from, from + 999);
      if (error) throw error;
      if (!data || data.length === 0) break;
      allRows = allRows.concat(data);
      if (data.length < 1000) break;
      from += 1000;
    }
    const map = {};
    allRows.forEach(r => { map[r.company_name] = r.ticker; });
    res.json({ map });
  } catch (e) {
    // Table may not exist yet
    res.json({ map: {} });
  }
});

app.post('/api/ticker-cache', auth, async (req, res) => {
  try {
    const { mappings } = req.body;
    if (!mappings || typeof mappings !== 'object') return res.status(400).json({ error: 'Invalid' });
    const rows = Object.entries(mappings)
      .filter(([k, v]) => k && v && v !== 'UNKNOWN')
      .map(([k, v]) => ({
        company_name: k.toLowerCase().trim(),
        ticker: v.toUpperCase().trim(),
        verified: false
      }));
    if (rows.length) {
      try {
        await supabase.from('ticker_cache').upsert(rows, { onConflict: 'company_name' });
      } catch(e) {
        return res.status(500).json({ error: 'ticker_cache table not created. Run migration v3 SQL.' });
      }
    }
    res.json({ success: true, saved: rows.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// PRICES — NSE API primary, Yahoo/Stooq/AI fallback
// ══════════════════════════════════════════════════════════════════════════

// NSE requires a session cookie before you can hit data endpoints.
// We maintain it in memory and refresh when expired.
let nseCookies = null;
let nseCookieTime = 0;

async function getNSECookies() {
  // Reuse cookies for 5 minutes
  if (nseCookies && (Date.now() - nseCookieTime) < 5 * 60 * 1000) {
    return nseCookies;
  }
  try {
    const resp = await fetch('https://www.nseindia.com/get-quotes/equity?symbol=RELIANCE', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
      },
      signal: AbortSignal.timeout(8000)
    });
    const cookies = resp.headers.raw?.()['set-cookie'] || resp.headers.get('set-cookie');
    if (cookies) {
      nseCookies = Array.isArray(cookies) ? cookies.map(c => c.split(';')[0]).join('; ') : cookies.split(';')[0];
      nseCookieTime = Date.now();
      return nseCookies;
    }
  } catch (e) {
    console.log('NSE cookie fetch failed:', e.message);
  }
  return null;
}

// Primary: NSE India's own API (free, reliable for NSE stocks)
async function fetchFromNSE(ticker, exchange) {
  if (exchange !== 'NSE') throw new Error('NSE API only supports NSE stocks');

  const cookies = await getNSECookies();
  if (!cookies) throw new Error('Could not establish NSE session');

  const url = `https://www.nseindia.com/api/quote-equity?symbol=${encodeURIComponent(ticker)}`;
  const resp = await fetch(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'en-US,en;q=0.9',
      'Referer': 'https://www.nseindia.com/get-quotes/equity?symbol=' + ticker,
      'Cookie': cookies,
      'X-Requested-With': 'XMLHttpRequest'
    },
    signal: AbortSignal.timeout(8000)
  });
  if (!resp.ok) throw new Error('NSE HTTP ' + resp.status);
  const data = await resp.json();
  const info = data?.priceInfo;
  if (!info || !info.lastPrice) throw new Error('NSE no price data');
  return {
    ltp: info.lastPrice,
    prev_close: info.previousClose,
    day_change_pct: info.pChange || 0,
    currency: 'INR',
    market_state: info.intraDayHighLow ? 'LIVE' : 'CLOSED',
    source: 'nse'
  };
}

// PRIMARY: Dhan Market Feed API (batch — up to 1000 tickers per call)
const DHAN_TOKEN = process.env.DHAN_ACCESS_TOKEN || '';
const DHAN_CLIENT_ID = process.env.DHAN_CLIENT_ID || '1000000290';

async function fetchFromDhan(tickers) {
  if (!DHAN_TOKEN) throw new Error('No Dhan token');

  const nse = tickers.filter(t => t.exchange === 'NSE').map(t => t.ticker);
  const bse = tickers.filter(t => t.exchange === 'BSE').map(t => t.ticker);

  const body = {};
  if (nse.length) body['NSE_EQ'] = nse;
  if (bse.length) body['BSE_EQ'] = bse;
  if (!Object.keys(body).length) throw new Error('No valid tickers');

  // Use /quote endpoint — returns OHLC so we can compute day change
  const resp = await fetch('https://api.dhan.co/v2/marketfeed/quote', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'access-token': DHAN_TOKEN,
      'client-id': DHAN_CLIENT_ID
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000)
  });

  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`Dhan HTTP ${resp.status}: ${txt.substring(0, 100)}`);
  }

  const json = await resp.json();
  const data = json.data || json;
  const results = {};

  for (const [segment, stocks] of Object.entries(data)) {
    if (!stocks || typeof stocks !== 'object') continue;
    for (const [ticker, info] of Object.entries(stocks)) {
      if (!info || typeof info !== 'object') continue;
      const ltp = info.last_price || info.ltp || 0;
      // Dhan quote response: ohlc.close is PREVIOUS day's close
      const prevClose = info.ohlc?.close || info.prev_close || ltp;
      const dayPct = prevClose && prevClose !== ltp ? ((ltp - prevClose) / prevClose) * 100 : 0;
      if (ltp > 0) {
        results[ticker] = {
          ltp,
          prev_close: prevClose,
          day_change_pct: Math.round(dayPct * 100) / 100,
          currency: 'INR',
          market_state: 'LIVE',
          source: 'dhan'
        };
      }
    }
  }
  return results;
}

// Fallback 1: Yahoo Finance (proxy via query1)
async function fetchFromYahoo(ticker, exchange) {
  let symbol = ticker;
  if (exchange === 'NSE') symbol = ticker + '.NS';
  else if (exchange === 'BSE') symbol = ticker + '.BO';

  const url = `https://query1.finance.yahoo.com/v8/finance/chart/${symbol}?interval=1d&range=5d`;
  const resp = await fetch(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Accept': 'application/json',
      'Accept-Language': 'en-US,en;q=0.9',
      'Origin': 'https://finance.yahoo.com',
      'Referer': 'https://finance.yahoo.com/'
    },
    signal: AbortSignal.timeout(10000)
  });
  if (!resp.ok) throw new Error('Yahoo HTTP ' + resp.status);
  const data = await resp.json();
  const meta = data?.chart?.result?.[0]?.meta;
  if (!meta) throw new Error('Yahoo no data');
  return {
    ltp: meta.regularMarketPrice || meta.previousClose,
    prev_close: meta.previousClose,
    day_change_pct: meta.previousClose
      ? ((meta.regularMarketPrice - meta.previousClose) / meta.previousClose) * 100
      : 0,
    currency: meta.currency,
    market_state: meta.marketState,
    source: 'yahoo'
  };
}

// Fallback 2: Stooq (free, no auth)
async function fetchFromStooq(ticker, exchange) {
  let symbol = ticker.toLowerCase();
  if (exchange === 'NSE' || exchange === 'BSE') symbol = ticker.toLowerCase() + '.in';
  else if (exchange === 'NYSE' || exchange === 'NASDAQ') symbol = ticker.toLowerCase() + '.us';

  const url = `https://stooq.com/q/l/?s=${symbol}&f=sd2t2ohlcv&h&e=csv`;
  const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
  if (!resp.ok) throw new Error('Stooq HTTP ' + resp.status);
  const text = await resp.text();
  const lines = text.trim().split('\n');
  if (lines.length < 2) throw new Error('Stooq no data');
  const cols = lines[1].split(',');
  const close = parseFloat(cols[6]);
  const open = parseFloat(cols[3]);
  if (!close || isNaN(close)) throw new Error('Stooq invalid data');
  return {
    ltp: close,
    prev_close: open,
    day_change_pct: open ? ((close - open) / open) * 100 : 0,
    currency: 'INR',
    market_state: 'UNKNOWN',
    source: 'stooq'
  };
}

// Last resort: AI web search
async function fetchFromAI(ticker, exchange) {
  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 300,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{
        role: 'user',
        content: `Current stock price and today's % change for ${ticker} on ${exchange}. Return ONLY this JSON: {"ltp":0.0,"day_change_pct":0.0}. No markdown.`
      }]
    });
    const text = response.content.filter(c => c.type === 'text').map(c => c.text).join('');
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
    return {
      ltp: parsed.ltp,
      prev_close: parsed.ltp / (1 + parsed.day_change_pct / 100),
      day_change_pct: parsed.day_change_pct,
      currency: 'INR',
      market_state: 'UNKNOWN',
      source: 'ai'
    };
  } catch (e) {
    throw new Error('AI fetch failed: ' + e.message);
  }
}

app.post('/api/prices', auth, async (req, res) => {
  try {
    const { tickers } = req.body;
    const results = {};

    // Try Dhan FIRST — batch call for ALL tickers at once (fastest)
    if (DHAN_TOKEN) {
      try {
        const dhanResults = await fetchFromDhan(tickers);
        Object.assign(results, dhanResults);
        const found = Object.keys(dhanResults).length;
        console.log(`Dhan: ${found}/${tickers.length} prices fetched`);
        // For any tickers Dhan missed, fall through to Yahoo below
      } catch (e) {
        console.log(`Dhan batch failed: ${e.message} — falling back to Yahoo`);
      }
    }

    // For any tickers not fetched by Dhan, try Yahoo/Stooq individually
    const missing = tickers.filter(({ ticker }) => !results[ticker]);
    if (missing.length) {
      getNSECookies().catch(() => {});
      await Promise.all(missing.map(async ({ ticker, exchange }) => {
        try { results[ticker] = await fetchFromYahoo(ticker, exchange); return; }
        catch (e1) { console.log(`Yahoo failed for ${ticker}: ${e1.message}`); }

        if (exchange === 'NSE') {
          try { results[ticker] = await fetchFromNSE(ticker, exchange); return; }
          catch (e0) { console.log(`NSE failed for ${ticker}: ${e0.message}`); }
        }

        try { results[ticker] = await fetchFromStooq(ticker, exchange); return; }
        catch (e2) { console.log(`Stooq failed for ${ticker}: ${e2.message}`); }

        try { results[ticker] = await fetchFromAI(ticker, exchange); }
        catch (e3) { console.error(`All sources failed for ${ticker}`); }
      }));
    }

    console.log(`Prices total: ${Object.keys(results).length}/${tickers.length} fetched`);
    res.json(results);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// AI ROUTES — all Anthropic calls happen here (API key never exposed)
// ══════════════════════════════════════════════════════════════════════════

// Parse uploaded file (image/PDF) to extract holdings
app.post('/api/ai/parse-file', auth, async (req, res) => {
  try {
    const { base64, mediaType } = req.body;
    const isImg = mediaType.startsWith('image/');
    const prompt = `You are looking at a portfolio/holdings spreadsheet or screenshot. Extract ALL stock holdings visible.

For each row, identify:
- ticker: The stock name. If it's a short/informal name like "skygold" or "concord", convert it to the full NSE ticker symbol (e.g. "skygold" → "SKYGOLD", "concord" → "CONCORDBIO"). Keep it UPPERCASE.
- exchange: "NSE" for Indian stocks unless clearly NYSE/NASDAQ/BSE
- qty: The quantity/shares column (as a number)
- avgCost: The buy price / cost per share (as a number)
- buyDate: The buy date in YYYY-MM-DD format, or null if not shown

Return ONLY a valid JSON array, no markdown, no explanation, nothing else:
[{"ticker":"RELIANCE","exchange":"NSE","qty":100,"avgCost":2400.50,"buyDate":null}]

If the image is unclear or has no stock data, return: []`;

    const content = isImg
      ? [{ type: 'image', source: { type: 'base64', media_type: mediaType, data: base64 } }, { type: 'text', text: prompt }]
      : [{ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: base64 } }, { type: 'text', text: prompt }];

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 2000,
      messages: [{ role: 'user', content }]
    });
    const text = response.content.filter(c => c.type === 'text').map(c => c.text).join('');
    console.log('AI raw response:', text.substring(0, 500));

    // Try to extract JSON array even if surrounded by other text
    let cleaned = text.replace(/```json|```/g, '').trim();
    const jsonMatch = cleaned.match(/\[[\s\S]*\]/);
    if (jsonMatch) cleaned = jsonMatch[0];

    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (parseErr) {
      console.error('JSON parse failed. Raw text:', text);
      return res.status(500).json({ error: 'AI returned unreadable data. The image might be too blurry or complex. Try a clearer screenshot or add stocks manually.' });
    }

    if (!Array.isArray(parsed)) parsed = [];
    res.json({ holdings: parsed });
  } catch (e) {
    console.error('Parse-file error:', e);
    res.status(500).json({ error: 'Could not parse file: ' + e.message });
  }
});

// Fetch daily news for portfolio stocks
app.post('/api/ai/news', auth, async (req, res) => {
  try {
    const { tickers } = req.body;
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1200,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{ role: 'user', content: `Latest news last 24 hours for: ${tickers.join(', ')}. Give earnings, analyst calls, corporate actions, significant moves. Summarize per stock. Only include stocks with actual news.` }]
    });
    const text = response.content.filter(c => c.type === 'text').map(c => c.text).join('\n');
    res.json({ news: text });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Answer any portfolio question
// Helper: detect credit/auth errors and return friendly message
function parseAIError(e) {
  const msg = e.message || '';
  if (msg.includes('credit balance is too low') || msg.includes('insufficient_quota')) {
    return { friendly: 'AI features unavailable — please top up Anthropic API credits at console.anthropic.com/settings/billing', code: 'credits_exhausted' };
  }
  if (msg.includes('rate_limit') || msg.includes('429')) {
    return { friendly: 'AI is rate-limited — please wait a minute and try again', code: 'rate_limit' };
  }
  if (msg.includes('invalid_api_key') || msg.includes('authentication')) {
    return { friendly: 'AI not configured — check ANTHROPIC_API_KEY on server', code: 'auth' };
  }
  return { friendly: msg, code: 'unknown' };
}

app.post('/api/ai/ask', auth, async (req, res) => {
  try {
    const { question, tickers } = req.body;
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1000,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{ role: 'user', content: `My portfolio: ${tickers}. Question: ${question}. Search and answer with current information.` }]
    });
    const text = response.content.filter(c => c.type === 'text').map(c => c.text).join('\n');
    res.json({ answer: text });
  } catch (e) {
    const parsed = parseAIError(e);
    res.status(500).json({ error: parsed.friendly, code: parsed.code });
  }
});

// Dedicated ticker lookup — NO web search, returns clean JSON
app.post('/api/ai/lookup-tickers', auth, async (req, res) => {
  try {
    const { names } = req.body;
    if (!Array.isArray(names) || names.length === 0) return res.json({ map: {} });
    const list = names.map((n, i) => `${i+1}. ${n}`).join('\n');
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 2000,
      messages: [{
        role: 'user',
        content: `Convert these Indian company names to their NSE ticker symbols. Return ONLY a valid JSON object. No markdown, no code fences, no explanation.

Examples of mappings:
- "State Bank of India" or "SBI" → "SBIN"
- "Mahindra & Mahindra" or "M&M" → "M&M"
- "LT Foods" → "DAAWAT"
- "Reliance Industries" or "Reliance" → "RELIANCE"
- "Tata Consultancy Services" or "TCS" → "TCS"
- "HDFC Bank" → "HDFCBANK"
- "Adani Enterprises" or "Adani Enterpris" → "ADANIENT"

If you cannot confidently identify a ticker, use "UNKNOWN".

Input names:
${list}

Return format (JSON only, no other text):
{"Name1":"TICKER1","Name2":"TICKER2",...}`
      }]
    });
    let text = response.content.filter(c => c.type === 'text').map(c => c.text).join('\n').trim();
    text = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) text = jsonMatch[0];
    let map = {};
    try { map = JSON.parse(text); } catch(e) {
      console.error('Ticker JSON parse failed:', text.substring(0, 200));
      return res.json({ map: {}, error: 'AI returned invalid JSON' });
    }
    res.json({ map });
  } catch (e) {
    const parsed = parseAIError(e);
    console.error('Ticker lookup error:', parsed.friendly);
    res.status(500).json({ error: parsed.friendly, code: parsed.code });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ══════════════════════════════════════════════════════════════════════════

app.post('/api/notifications/settings', auth, async (req, res) => {
  const { notify_email } = req.body;
  await supabase.from('users').update({ notify_email }).eq('id', req.user.id);
  res.json({ success: true });
});

async function buildAndSendSummary(userId, userEmail, userName) {
  const [{ data: holdings }, { data: transactions }] = await Promise.all([
    supabase.from('holdings').select('*').eq('user_id', userId),
    supabase.from('transactions').select('*').eq('user_id', userId)
  ]);
  if (!holdings?.length) return;

  const tickers = holdings.map(h => ({ ticker: h.ticker, exchange: h.exchange }));

  // Fetch prices
  const priceResp = await fetch(`${process.env.SERVER_URL || 'http://localhost:3000'}/api/prices`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer internal' },
    body: JSON.stringify({ tickers })
  }).catch(() => null);
  const prices = priceResp ? await priceResp.json().catch(() => ({})) : {};

  // Fetch news
  let news = '';
  try {
    const nr = await anthropic.messages.create({
      model: 'claude-sonnet-4-6', max_tokens: 800,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{ role: 'user', content: `Latest news for: ${holdings.map(h=>h.ticker).join(', ')}. 1-2 lines per stock, only if there is real news.` }]
    });
    news = nr.content.filter(c => c.type === 'text').map(c => c.text).join('\n');
  } catch { news = 'News unavailable today.'; }

  // Build summary
  let totalInvested = 0, totalValue = 0, totalDayPnL = 0;
  const rows = holdings.map(h => {
    const p = prices[h.ticker];
    const ltp = p?.ltp || h.avg_cost;
    const dayPct = p?.day_change_pct || 0;
    const invested = h.qty * h.avg_cost;
    const value = h.qty * ltp;
    const pnl = value - invested;
    const retPct = invested > 0 ? (pnl / invested) * 100 : 0;
    const dayPnL = p ? value - value / (1 + dayPct / 100) : 0;
    totalInvested += invested; totalValue += value; totalDayPnL += dayPnL;
    const c = pnl >= 0 ? '#16a34a' : '#dc2626';
    return `<tr><td style="padding:8px 10px;font-weight:600">${h.ticker}</td><td style="padding:8px 10px">${h.qty}</td><td style="padding:8px 10px">₹${h.avg_cost?.toFixed(2)}</td><td style="padding:8px 10px">₹${ltp.toFixed(2)}</td><td style="padding:8px 10px;color:${dayPct>=0?'#16a34a':'#dc2626'}">${dayPct>=0?'+':''}${dayPct.toFixed(2)}%</td><td style="padding:8px 10px;color:${c};font-weight:600">${pnl>=0?'+':''}₹${Math.round(pnl).toLocaleString('en-IN')}</td><td style="padding:8px 10px;color:${c}">${retPct>=0?'+':''}${retPct.toFixed(2)}%</td></tr>`;
  }).join('');

  const ret = totalValue - totalInvested;
  const retPct = totalInvested > 0 ? (ret / totalInvested) * 100 : 0;
  const dayPct = (totalValue - totalDayPnL) > 0 ? (totalDayPnL / (totalValue - totalDayPnL)) * 100 : 0;
  const sign = v => v >= 0 ? '+' : '';
  const fmtCur = v => { const a=Math.abs(v); if(a>=1e7) return (v<0?'-':'')+'₹'+(a/1e7).toFixed(2)+'Cr'; if(a>=1e5) return (v<0?'-':'')+'₹'+(a/1e5).toFixed(2)+'L'; return (v<0?'-':'')+'₹'+Math.round(a).toLocaleString('en-IN'); };

  const html = `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f8fafc">
<div style="background:#0f172a;border-radius:12px;padding:20px 24px;margin-bottom:16px">
  <h1 style="color:#fff;margin:0 0 4px;font-size:22px">📊 FolioTrack</h1>
  <p style="color:#94a3b8;margin:0;font-size:14px">Daily Summary · ${new Date().toDateString()}</p>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
  ${[['Portfolio Value', fmtCur(totalValue), ''], ['Day P&L', fmtCur(totalDayPnL), dayPct>=0?'#16a34a':'#dc2626'], ['Total Return', sign(ret)+fmtCur(ret), ret>=0?'#16a34a':'#dc2626'], ['Invested', fmtCur(totalInvested), '']].map(([l,v,c])=>`<div style="background:#fff;border-radius:10px;padding:14px"><div style="font-size:11px;color:#64748b;text-transform:uppercase;margin-bottom:4px">${l}</div><div style="font-size:18px;font-weight:700;color:${c||'#0f172a'}">${v}</div></div>`).join('')}
</div>
<div style="background:#fff;border-radius:10px;padding:16px;margin-bottom:16px;overflow-x:auto">
  <h3 style="margin:0 0 12px;font-size:14px;color:#475569;text-transform:uppercase;letter-spacing:0.05em">Holdings</h3>
  <table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr style="font-size:11px;color:#94a3b8;text-transform:uppercase"><th style="padding:6px 10px;text-align:left">Stock</th><th style="padding:6px 10px;text-align:left">Qty</th><th style="padding:6px 10px;text-align:left">Avg</th><th style="padding:6px 10px;text-align:left">LTP</th><th style="padding:6px 10px;text-align:left">Day</th><th style="padding:6px 10px;text-align:left">P&L</th><th style="padding:6px 10px;text-align:left">Return</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>
<div style="background:#fff;border-radius:10px;padding:16px;margin-bottom:16px">
  <h3 style="margin:0 0 10px;font-size:14px;color:#475569;text-transform:uppercase;letter-spacing:0.05em">📰 Today's News</h3>
  <div style="font-size:13px;line-height:1.7;color:#334155;white-space:pre-wrap">${news}</div>
</div>
<p style="font-size:11px;color:#94a3b8;text-align:center">FolioTrack · To stop emails, log in → Settings → Notifications</p>
</body></html>`;

  await sendEmail({
    to: userEmail,
    subject: `📊 ${userName}'s Portfolio · ${sign(dayPct)}${dayPct.toFixed(2)}% today · ${new Date().toDateString()}`,
    html
  });
}

// ── Daily cron: 4:30 PM IST = 11:00 UTC, weekdays ────────────────────────
cron.schedule('0 11 * * 1-5', async () => {
  console.log('⏰ Sending daily summaries...');
  const { data: users } = await supabase.from('users').select('id,email,name').eq('notify_email', true);
  for (const user of (users || [])) {
    try { await buildAndSendSummary(user.id, user.email, user.name); console.log('✅ Sent to', user.email); }
    catch (e) { console.error('Failed for', user.email, e.message); }
  }
}, { timezone: 'Asia/Kolkata' });

// Manual trigger (for testing)
app.post('/api/notifications/send-now', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
    await buildAndSendSummary(user.id, user.email, user.name);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Start ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 FolioTrack backend running on port ${PORT}`));
