require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieSession = require("cookie-session");
const bcrypt = require("bcryptjs");
const fetch = require("node-fetch");

const db = require("./db");
const solana = require("./solana");

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.use(
  cookieSession({
    name: "metamob_session",
    secret: process.env.SESSION_SECRET,
    maxAge: 12 * 60 * 60 * 1000, // 12 hours
    httpOnly: true,
    sameSite: "lax"
  })
);

// ---------------------------------------------------------------------------
// Admin auth (server-side only - the password/hash never reach the browser)
// ---------------------------------------------------------------------------
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(401).json({ error: "Admin authentication required" });
}

app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing email or password" });

  if (email !== process.env.ADMIN_EMAIL) {
    return res.status(401).json({ error: "Invalid admin credentials" });
  }
  if (!process.env.ADMIN_PASSWORD_HASH) {
    return res.status(500).json({ error: "Server has no ADMIN_PASSWORD_HASH configured" });
  }
  const ok = bcrypt.compareSync(password, process.env.ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ error: "Invalid admin credentials" });

  req.session.isAdmin = true;
  res.json({ ok: true });
});

app.post("/api/admin/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

app.get("/api/admin/session", (req, res) => {
  res.json({ isAdmin: !!(req.session && req.session.isAdmin) });
});

// ---------------------------------------------------------------------------
// Wallet login - proves the caller actually controls the wallet they claim.
// The frontend calls provider.signMessage() on a message we return here,
// then POSTs the signature back. This never moves funds.
// ---------------------------------------------------------------------------
app.get("/api/auth/challenge", (req, res) => {
  const nonce = Math.random().toString(36).slice(2);
  res.json({ message: `Sign in to Metamob Arena. Nonce: ${nonce}` });
});

app.post("/api/auth/verify", (req, res) => {
  const { wallet, message, signature } = req.body || {};
  if (!wallet || !message || !signature) return res.status(400).json({ error: "Missing fields" });
  try {
    const valid = solana.verifyWalletSignature(wallet, message, signature);
    if (!valid) return res.status(401).json({ error: "Signature does not match wallet" });
    req.session.wallet = wallet;
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

function requireWalletSession(req, res, next) {
  if (req.session && req.session.wallet) return next();
  return res.status(401).json({ error: "Wallet login required (sign the auth message first)" });
}

// ---------------------------------------------------------------------------
// Games - registered by admin, with a server-side embeddability check
// (fixes "some games weren't loading": most of the time it's the target
// site sending X-Frame-Options / CSP frame-ancestors that blocks iframing,
// and there is no client-side way around that - it's the site's choice).
// ---------------------------------------------------------------------------
app.get("/api/games", (req, res) => {
  res.json(db.get("games").value());
});

app.post("/api/admin/games/check-url", requireAdmin, async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: "Missing url" });
  if (url === "about:blank" || url.startsWith("http://localhost")) {
    return res.json({ embeddable: true, note: "Local/blank URL - can't be checked remotely, assumed OK." });
  }
  try {
    const resp = await fetch(url, { method: "GET", redirect: "follow", timeout: 8000 });
    const xfo = resp.headers.get("x-frame-options");
    const csp = resp.headers.get("content-security-policy") || "";
    const blockedByXfo = xfo && /deny|sameorigin/i.test(xfo);
    const blockedByCsp = /frame-ancestors\s+'none'/i.test(csp);
    if (blockedByXfo || blockedByCsp) {
      return res.json({
        embeddable: false,
        note: `This site sends ${blockedByXfo ? "X-Frame-Options: " + xfo : "a CSP frame-ancestors"} which blocks embedding in an iframe. It cannot be fixed from our side - the site owner would need to allow it, or you'd need a game that permits embedding.`
      });
    }
    return res.json({ embeddable: true, note: "No obvious embedding block detected." });
  } catch (e) {
    return res.json({ embeddable: null, note: "Could not reach the URL to check: " + e.message });
  }
});

app.post("/api/admin/games", requireAdmin, (req, res) => {
  const { title, type, url } = req.body || {};
  if (!title || !type || !url) return res.status(400).json({ error: "Missing fields" });
  const id = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
  const games = db.get("games");
  const existing = games.find({ id }).value();
  if (existing) {
    games.find({ id }).assign({ title, type, url }).write();
  } else {
    games.push({ id, title, type, url, embeddable: null }).write();
  }
  res.json(db.get("games").value());
});

app.delete("/api/admin/games/:id", requireAdmin, (req, res) => {
  db.get("games").remove({ id: req.params.id }).write();
  res.json(db.get("games").value());
});

// ---------------------------------------------------------------------------
// Presence - "what is everyone playing right now"
// ---------------------------------------------------------------------------
app.post("/api/presence", requireWalletSession, (req, res) => {
  const { gameId, gameTitle } = req.body || {};
  db.get("presence")
    .set(req.session.wallet, { gameId, gameTitle, since: Date.now() })
    .write();
  res.json({ ok: true });
});

app.get("/api/presence", (req, res) => {
  const raw = db.get("presence").value();
  const cutoff = Date.now() - 5 * 60 * 1000; // consider "online" if seen in last 5 min
  const list = Object.entries(raw)
    .filter(([, v]) => v.since > cutoff)
    .map(([wallet, v]) => ({ wallet: wallet.slice(0, 4) + "..." + wallet.slice(-4), ...v }));
  res.json(list);
});

// ---------------------------------------------------------------------------
// Faucet - REAL on-chain payout, server-enforced cooldown (can't be reset
// by clearing localStorage anymore since the cooldown now lives server-side).
// ---------------------------------------------------------------------------
app.post("/api/faucet/claim", requireWalletSession, async (req, res) => {
  const wallet = req.session.wallet;
  const cooldownMs = Number(process.env.FAUCET_COOLDOWN_MINUTES) * 60 * 1000;
  const last = db.get("faucetClaims").get(wallet).value();
  const now = Date.now();

  if (last && now - last < cooldownMs) {
    const minutesLeft = Math.ceil((cooldownMs - (now - last)) / 60000);
    return res.status(429).json({ error: `Already claimed. Try again in ${minutesLeft} minutes.` });
  }

  try {
    const amount = Number(process.env.FAUCET_AMOUNT);
    const signature = await solana.payoutTokens(wallet, amount);
    db.get("faucetClaims").set(wallet, now).write();
    res.json({ ok: true, amount, signature });
  } catch (e) {
    res.status(500).json({ error: "Payout failed: " + e.message });
  }
});

// ---------------------------------------------------------------------------
// Prediction market (custodial model - see README for the trust tradeoffs).
// Flow:
//  1. Admin opens a market tied to a game ("Will Player beat the CPU?").
//  2. A user's wallet signs & sends a real SPL transfer of their stake to
//     the treasury wallet (client-side, via their own wallet - never our key).
//  3. User POSTs the resulting tx signature; the backend verifies on-chain
//     that the transfer really happened before it counts the bet.
//  4. Admin resolves the market with the true outcome; backend computes
//     each winner's share of the losing pool (minus a fee) and sends real
//     payouts from the treasury.
// ---------------------------------------------------------------------------
app.get("/api/markets", (req, res) => {
  const { gameId, status } = req.query;
  let markets = db.get("markets").value();
  if (gameId) markets = markets.filter((m) => m.gameId === gameId);
  if (status) markets = markets.filter((m) => m.status === status);
  res.json(markets);
});

app.post("/api/admin/markets", requireAdmin, (req, res) => {
  const { gameId, gameTitle, question, sides } = req.body || {};
  if (!gameId || !question || !Array.isArray(sides) || sides.length < 2) {
    return res.status(400).json({ error: "Need gameId, question, and at least 2 sides" });
  }
  const market = {
    id: "mkt_" + Date.now(),
    gameId,
    gameTitle,
    question,
    sides,                 // e.g. ["Player wins", "CPU wins"]
    status: "open",        // open -> resolved
    bets: [],              // { wallet, side, amount, signature }
    outcome: null,
    createdAt: Date.now()
  };
  db.get("markets").push(market).write();
  res.json(market);
});

app.post("/api/markets/:id/bet", requireWalletSession, async (req, res) => {
  const { side, amount, signature } = req.body || {};
  const market = db.get("markets").find({ id: req.params.id }).value();
  if (!market) return res.status(404).json({ error: "Market not found" });
  if (market.status !== "open") return res.status(400).json({ error: "Market is closed" });
  if (!market.sides.includes(side)) return res.status(400).json({ error: "Invalid side" });
  if (!signature || !amount) return res.status(400).json({ error: "Missing signature or amount" });

  if (db.get("usedTxSignatures").get(signature).value()) {
    return res.status(400).json({ error: "This transaction has already been used for a bet" });
  }

  const verification = await solana.verifyStakeTransaction(signature, req.session.wallet, amount);
  if (!verification.ok) {
    return res.status(400).json({ error: "Could not verify on-chain stake: " + verification.reason });
  }

  db.get("markets")
    .find({ id: market.id })
    .get("bets")
    .push({ wallet: req.session.wallet, side, amount: verification.amount, signature })
    .write();
  db.get("usedTxSignatures").set(signature, true).write();

  res.json({ ok: true });
});

app.post("/api/admin/markets/:id/resolve", requireAdmin, async (req, res) => {
  const { outcome } = req.body || {};
  const market = db.get("markets").find({ id: req.params.id }).value();
  if (!market) return res.status(404).json({ error: "Market not found" });
  if (market.status !== "open") return res.status(400).json({ error: "Market already resolved" });
  if (!market.sides.includes(outcome)) return res.status(400).json({ error: "Invalid outcome" });

  const winningBets = market.bets.filter((b) => b.side === outcome);
  const losingBets = market.bets.filter((b) => b.side !== outcome);
  const winningPool = winningBets.reduce((s, b) => s + b.amount, 0);
  const losingPool = losingBets.reduce((s, b) => s + b.amount, 0);
  const feeBps = Number(process.env.MARKET_FEE_BPS || 0);
  const distributable = losingPool * (1 - feeBps / 10000);

  const payouts = [];
  for (const bet of winningBets) {
    const share = winningPool > 0 ? bet.amount / winningPool : 0;
    const winnings = bet.amount + distributable * share; // stake back + share of losers' pool
    try {
      const signature = await solana.payoutTokens(bet.wallet, winnings);
      payouts.push({ wallet: bet.wallet, amount: winnings, signature });
    } catch (e) {
      payouts.push({ wallet: bet.wallet, amount: winnings, error: e.message });
    }
  }

  db.get("markets")
    .find({ id: market.id })
    .assign({ status: "resolved", outcome, payouts, resolvedAt: Date.now() })
    .write();

  res.json({ ok: true, payouts });
});

// ---------------------------------------------------------------------------
// Retirement vault - admin-sponsored wallets can lock tokens for a fixed
// period and receive a bonus on unlock, or exit early for a penalty.
// Deposits work the same way market stakes do: the user's own wallet signs
// a real SPL transfer to the treasury, and we verify it on-chain before
// creating the vault entry.
// ---------------------------------------------------------------------------
function vaultParamsFor(wallet) {
  const custom = db.get("sponsoredWallets").get(wallet).value();
  if (!custom) return null;
  return {
    lockDays: custom.lockDays ?? Number(process.env.DEFAULT_VAULT_LOCK_DAYS),
    bonusBps: custom.bonusBps ?? Number(process.env.DEFAULT_VAULT_BONUS_BPS),
    penaltyBps: custom.penaltyBps ?? Number(process.env.DEFAULT_VAULT_PENALTY_BPS)
  };
}

app.get("/api/admin/sponsored", requireAdmin, (req, res) => {
  res.json(db.get("sponsoredWallets").value());
});

app.post("/api/admin/sponsored", requireAdmin, (req, res) => {
  const { wallet, lockDays, bonusBps, penaltyBps } = req.body || {};
  if (!wallet) return res.status(400).json({ error: "Missing wallet" });
  db.get("sponsoredWallets")
    .set(wallet, {
      lockDays: lockDays != null ? Number(lockDays) : undefined,
      bonusBps: bonusBps != null ? Number(bonusBps) : undefined,
      penaltyBps: penaltyBps != null ? Number(penaltyBps) : undefined,
      addedAt: Date.now()
    })
    .write();
  res.json(db.get("sponsoredWallets").value());
});

app.delete("/api/admin/sponsored/:wallet", requireAdmin, (req, res) => {
  db.get("sponsoredWallets").unset(req.params.wallet).write();
  res.json(db.get("sponsoredWallets").value());
});

// What the connected wallet is eligible for (used by the frontend to decide
// whether to show the vault panel at all).
app.get("/api/vault/eligibility", requireWalletSession, (req, res) => {
  const params = vaultParamsFor(req.session.wallet);
  res.json({ eligible: !!params, params });
});

app.get("/api/vault/mine", requireWalletSession, (req, res) => {
  const deposits = db.get("vaultDeposits").filter({ wallet: req.session.wallet }).value();
  res.json(deposits);
});

app.post("/api/vault/deposit", requireWalletSession, async (req, res) => {
  const wallet = req.session.wallet;
  const params = vaultParamsFor(wallet);
  if (!params) return res.status(403).json({ error: "This wallet is not on the sponsored list" });

  const { amount, signature } = req.body || {};
  if (!amount || !signature) return res.status(400).json({ error: "Missing amount or signature" });

  if (db.get("usedTxSignatures").get(signature).value()) {
    return res.status(400).json({ error: "This transaction has already been used" });
  }
  const verification = await solana.verifyStakeTransaction(signature, wallet, amount);
  if (!verification.ok) {
    return res.status(400).json({ error: "Could not verify on-chain deposit: " + verification.reason });
  }

  const now = Date.now();
  const deposit = {
    id: "vault_" + now + "_" + Math.random().toString(36).slice(2, 7),
    wallet,
    amount: verification.amount,
    signature,
    depositedAt: now,
    unlockAt: now + params.lockDays * 24 * 60 * 60 * 1000,
    bonusBps: params.bonusBps,
    penaltyBps: params.penaltyBps,
    status: "locked",
    withdrawSignature: null
  };
  db.get("vaultDeposits").push(deposit).write();
  db.get("usedTxSignatures").set(signature, true).write();
  res.json(deposit);
});

app.post("/api/vault/:id/withdraw", requireWalletSession, async (req, res) => {
  const wallet = req.session.wallet;
  const deposit = db.get("vaultDeposits").find({ id: req.params.id, wallet }).value();
  if (!deposit) return res.status(404).json({ error: "Deposit not found" });
  if (deposit.status !== "locked") return res.status(400).json({ error: "Already withdrawn" });

  const now = Date.now();
  const matured = now >= deposit.unlockAt;
  const payoutAmount = matured
    ? deposit.amount * (1 + deposit.bonusBps / 10000)
    : deposit.amount * (1 - deposit.penaltyBps / 10000);

  try {
    const signature = await solana.payoutTokens(wallet, payoutAmount);
    db.get("vaultDeposits")
      .find({ id: deposit.id })
      .assign({ status: "withdrawn", withdrawSignature: signature, withdrawnEarly: !matured, payoutAmount })
      .write();
    res.json({ ok: true, matured, payoutAmount, signature });
  } catch (e) {
    res.status(500).json({ error: "Payout failed: " + e.message });
  }
});

app.get("/api/admin/vault/deposits", requireAdmin, (req, res) => {
  res.json(db.get("vaultDeposits").value());
});

// ---------------------------------------------------------------------------
app.get("/api/config/public", (req, res) => {
  res.json({
    tokenMint: process.env.TOKEN_MINT_ADDRESS,
    treasuryPublicKey: solana.treasuryPublicKey,
    faucetAmount: Number(process.env.FAUCET_AMOUNT)
  });
});

const port = process.env.PORT || 8787;
app.listen(port, () => console.log(`Metamob Arena backend listening on :${port}`));
