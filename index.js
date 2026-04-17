// FolioTrack — Secure Backend
// Handles: auth, portfolio storage, live prices, AI news, daily email digest
// Deploy on Railway (free) — see DEPLOY_GUIDE.md

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
const Anthropic = require('@anthropic-ai/sdk');
require('dotenv').config();

const app = express();
app.use(cors({ origin: process.env.CLIENT_URL || '*' }));
app.use(express.json());

// ── Clients ────────────────────────────────────────────────────────────────
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_APP_PASS }
});

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
  const [{ data: portfolio }, { data: transactions }] = await Promise.all([
    supabase.from('holdings').select('*').eq('user_id', req.user.id),
    supabase.from('transactions').select('*').eq('user_id', req.user.id).order('date', { ascending: true })
  ]);
  res.json({ portfolio: portfolio || [], transactions: transactions || [] });
});

// Add transaction (buy or sell)
app.post('/api/portfolio/transaction', auth, async (req, res) => {
  try {
    const { ticker, exchange, qty, price, date, type } = req.body;
    if (!ticker || !qty || !price || !date || !type) return res.status(400).json({ error: 'All fields required' });
    if (!price || price <= 0) return res.status(400).json({ error: 'Buy price is required — never assumed' });

    // Save transaction
    const { data: tx, error: txErr } = await supabase.from('transactions').insert({
      user_id: req.user.id, ticker: ticker.toUpperCase(), exchange, qty, price, date, type
    }).select().single();
    if (txErr) throw txErr;

    // Update holdings
    if (type === 'buy') {
      const { data: existing } = await supabase.from('holdings')
        .select('*').eq('user_id', req.user.id).eq('ticker', ticker.toUpperCase()).eq('exchange', exchange).single();

      if (existing) {
        const newQty = existing.qty + qty;
        const newAvg = (existing.avg_cost * existing.qty + price * qty) / newQty;
        await supabase.from('holdings').update({ qty: newQty, avg_cost: newAvg }).eq('id', existing.id);
      } else {
        await supabase.from('holdings').insert({
          user_id: req.user.id, ticker: ticker.toUpperCase(), exchange, qty, avg_cost: price, buy_date: date
        });
      }
    } else if (type === 'sell') {
      const { data: existing } = await supabase.from('holdings')
        .select('*').eq('user_id', req.user.id).eq('ticker', ticker.toUpperCase()).eq('exchange', exchange).single();
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

// Delete transaction
app.delete('/api/portfolio/transaction/:id', auth, async (req, res) => {
  await supabase.from('transactions').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// Bulk import (from file upload parsing)
app.post('/api/portfolio/import', auth, async (req, res) => {
  try {
    const { holdings } = req.body; // [{ ticker, exchange, qty, avgCost, buyDate }]
    const missing = [];
    for (const h of holdings) {
      if (!h.ticker) continue;
      if (!h.avgCost || h.avgCost <= 0) { missing.push(h.ticker.toUpperCase()); continue; }
      const { data: existing } = await supabase.from('holdings')
        .select('*').eq('user_id', req.user.id).eq('ticker', h.ticker.toUpperCase()).single();
      if (!existing) {
        await supabase.from('holdings').insert({
          user_id: req.user.id, ticker: h.ticker.toUpperCase(),
          exchange: h.exchange || 'NSE', qty: h.qty || 0,
          avg_cost: h.avgCost, buy_date: h.buyDate || new Date().toISOString().split('T')[0]
        });
      }
    }
    res.json({ success: true, imported: holdings.length, missingPrices: missing });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// PRICES — Yahoo Finance (free, no key needed)
// ══════════════════════════════════════════════════════════════════════════
app.post('/api/prices', auth, async (req, res) => {
  try {
    const { tickers } = req.body; // [{ ticker, exchange }]
    const results = {};

    await Promise.all(tickers.map(async ({ ticker, exchange }) => {
      // Build Yahoo Finance symbol
      let symbol = ticker;
      if (exchange === 'NSE') symbol = ticker + '.NS';
      else if (exchange === 'BSE') symbol = ticker + '.BO';

      try {
        const url = `https://query1.finance.yahoo.com/v8/finance/chart/${symbol}?interval=1d&range=5d`;
        const resp = await fetch(url, {
          headers: { 'User-Agent': 'Mozilla/5.0' }
        });
        const data = await resp.json();
        const meta = data?.chart?.result?.[0]?.meta;
        if (meta) {
          results[ticker] = {
            ltp: meta.regularMarketPrice || meta.previousClose,
            prev_close: meta.previousClose,
            day_change_pct: meta.previousClose
              ? ((meta.regularMarketPrice - meta.previousClose) / meta.previousClose) * 100
              : 0,
            currency: meta.currency,
            market_state: meta.marketState
          };
        }
      } catch (e) {
        console.error(`Price fetch failed for ${ticker}:`, e.message);
      }
    }));

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
    const content = isImg
      ? [{ type: 'image', source: { type: 'base64', media_type: mediaType, data: base64 } }, { type: 'text', text: 'Extract stock holdings from this image. Return ONLY a JSON array: [{"ticker":"","exchange":"NSE","qty":0,"avgCost":0,"buyDate":""}]. Set null for any missing value. Never assume prices.' }]
      : [{ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: base64 } }, { type: 'text', text: 'Extract stock holdings. Return ONLY JSON array: [{"ticker":"","exchange":"NSE","qty":0,"avgCost":0,"buyDate":""}]. Set null for any missing value.' }];

    const response = await anthropic.messages.create({ model: 'claude-sonnet-4-20250514', max_tokens: 1000, messages: [{ role: 'user', content }] });
    const text = response.content.filter(c => c.type === 'text').map(c => c.text).join('');
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
    res.json({ holdings: parsed });
  } catch (e) {
    res.status(500).json({ error: 'Could not parse file: ' + e.message });
  }
});

// Fetch daily news for portfolio stocks
app.post('/api/ai/news', auth, async (req, res) => {
  try {
    const { tickers } = req.body;
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
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
app.post('/api/ai/ask', auth, async (req, res) => {
  try {
    const { question, tickers } = req.body;
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{ role: 'user', content: `My portfolio: ${tickers}. Question: ${question}. Search and answer with current information.` }]
    });
    const text = response.content.filter(c => c.type === 'text').map(c => c.text).join('\n');
    res.json({ answer: text });
  } catch (e) {
    res.status(500).json({ error: e.message });
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
      model: 'claude-sonnet-4-20250514', max_tokens: 800,
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

  await mailer.sendMail({
    from: `FolioTrack <${process.env.EMAIL_USER}>`,
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
