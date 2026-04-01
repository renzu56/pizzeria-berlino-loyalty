
import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import QRCode from "qrcode";
import { Resend } from "resend";
import path from "path";
import crypto from "crypto";
import fs from "fs";
import { fileURLToPath } from "url";
import { prisma } from "./lib/prisma.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
app.use("/static", express.static(path.join(__dirname, "public"), { etag: true, maxAge: process.env.NODE_ENV === "production" ? "7d" : 0 }));

const PORT = Number(process.env.PORT || 3000);
const APP_URL = normalizeAppUrl(process.env.APP_URL, PORT);
const DEV_AUTO_VERIFY = process.env.DEV_AUTO_VERIFY === "true";
const BRAND_NAME = process.env.BRAND_NAME || "Pizza Berlino";
const BRAND_SUBTITLE = process.env.BRAND_SUBTITLE || "Pizza Loyalty Club";
const BRAND_LOGO_FILENAME = process.env.BRAND_LOGO_FILENAME || "1773058332279.jfif";
const SESSION_SECRET = process.env.SESSION_SECRET || "change_me_super_secret";
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 14);
const STAFF_PIN = process.env.STAFF_PIN || "2468";
const PASSWORD_RESET_EXPIRES_MINUTES = Number(process.env.PASSWORD_RESET_EXPIRES_MINUTES || 30);
const INSTAGRAM_URL = process.env.INSTAGRAM_URL || "https://www.instagram.com/pizza_berlino/";
const REVIEW_URL = process.env.REVIEW_URL || "https://g.page/r/CcF9V1iR1Es9EBM/review";
const WALLETWALLET_API_KEY = process.env.WALLETWALLET_API_KEY || "";
const WALLETWALLET_COLOR_PRESET = process.env.WALLETWALLET_COLOR_PRESET || "red";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;
const ADMIN_EMAILS = new Set((process.env.ADMIN_EMAILS || "").split(",").map(v => v.trim().toLowerCase()).filter(Boolean));

const brandLogoPath = path.join(__dirname, BRAND_LOGO_FILENAME);
const authRateStore = new Map();
const rewardDefs = [
  { id: "r15", title: "10% Rabatt", cost: 15, description: "10% Rabatt auf die nächste Bestellung." },
  { id: "r100", title: "Kostenloses Getränk", cost: 100, description: "Ein Getränk gratis." },
  { id: "r175", title: "50% Rabatt", cost: 175, description: "50% Rabatt auf die nächste Bestellung." },
  { id: "r300", title: "Kostenlose Pizza", cost: 300, description: "Eine Pizza gratis." }
];
const DAILY_CHECKIN_CONFIG = { label: "Daily Check-in", addPoints: 10, addPizzas: 0, oncePerDay: true };

app.use(securityHeaders);
app.use(originGuard);
app.use(noStoreHtml);

app.get("/brand-logo", (req, res) => {
  if (!fs.existsSync(brandLogoPath)) return res.status(404).send("Logo not found");
  res.sendFile(brandLogoPath);
});

function normalizeAppUrl(rawValue, port) {
  const fallback = `http://localhost:${port}`;
  const value = String(rawValue || "").trim().replace(/\/$/, "");
  if (!value) return fallback;
  if (/^https?:\/\//i.test(value)) return value;
  const isLocal = /^(localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?$/i.test(value);
  return `${isLocal ? "http" : "https"}://${value}`;
}

function securityHeaders(req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(self), geolocation=(), microphone=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://unpkg.com; connect-src 'self' https://api.walletwallet.dev; object-src 'none'"
  );
  next();
}

function originGuard(req, res, next) {
  if (req.method === "POST") {
    const origin = String(req.headers.origin || "");
    const referer = String(req.headers.referer || "");
    if (origin && !origin.startsWith(APP_URL)) return res.status(403).send("Ungültige Anfrage");
    if (!origin && referer && !referer.startsWith(APP_URL)) return res.status(403).send("Ungültige Anfrage");
  }
  next();
}

function noStoreHtml(req, res, next) {
  if (String(req.headers.accept || "").includes("text/html")) {
    res.setHeader("Cache-Control", "no-store");
  }
  next();
}

function rateLimit({ windowMs, max, store, name }) {
  return (req, res, next) => {
    const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
    const key = `${name}:${ip}`;
    const now = Date.now();
    const current = store.get(key);
    if (!current || current.resetAt < now) {
      store.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (current.count >= max) return res.status(429).send("Zu viele Anfragen. Bitte kurz warten.");
    current.count += 1;
    next();
  };
}

function uid() { return crypto.randomUUID(); }
function nowDate() { return new Date(); }
function nowIso() { return nowDate().toISOString(); }
function dayKey(date = new Date()) {
  return new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Berlin", year: "numeric", month: "2-digit", day: "2-digit" }).format(date);
}
function absoluteUrl(pathname) { return new URL(pathname, `${APP_URL}/`).toString(); }
function formatDateTime(value) {
  return value ? new Date(value).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }) : "";
}
function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, ch => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[ch]));
}
function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function verifySession(token) {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  if (!safeEqual(sig, expected)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (parsed.exp && Number(parsed.exp) < Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}
function signTimedToken(payload, expiresMinutes = 30) {
  return signSession({ ...payload, exp: Date.now() + Math.max(1, expiresMinutes) * 60 * 1000 });
}
function verifyTimedToken(token, purpose) {
  const payload = verifySession(token);
  if (!payload) return null;
  if (purpose && payload.purpose !== purpose) return null;
  if (!payload.exp || Number(payload.exp) < Date.now()) return null;
  return payload;
}
function passwordResetFingerprint(user) {
  return crypto.createHash("sha256").update(String(user?.passwordHash || "")).digest("hex").slice(0, 24);
}
function passwordPolicyHint() {
  return "Mindestens 10 Zeichen mit Groß-/Kleinbuchstaben, Zahl und Sonderzeichen.";
}
function validatePassword(password, email = "", name = "") {
  const value = String(password || "");
  const issues = [];
  if (value.length < 10) issues.push("mindestens 10 Zeichen");
  if (!/[a-z]/.test(value)) issues.push("einen Kleinbuchstaben");
  if (!/[A-Z]/.test(value)) issues.push("einen Großbuchstaben");
  if (!/\d/.test(value)) issues.push("eine Zahl");
  if (!/[^A-Za-z0-9]/.test(value)) issues.push("ein Sonderzeichen");
  if (email && value.toLowerCase().includes(String(email).split("@")[0].toLowerCase())) issues.push("nicht deinen E-Mail-Namen");
  for (const part of String(name || "").toLowerCase().split(/\s+/)) {
    if (part.length >= 3 && value.toLowerCase().includes(part)) {
      issues.push("nicht Teile deines Namens");
      break;
    }
  }
  return { valid: issues.length === 0, message: issues.length ? `Passwort braucht ${issues.join(", ")}.` : "" };
}
function sessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: APP_URL.startsWith("https://") || process.env.NODE_ENV === "production",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
    path: "/"
  };
}
function setSession(res, user) {
  res.cookie("session", signSession({
    userId: user.id,
    email: user.email,
    role: user.role,
    exp: Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
  }), sessionCookieOptions());
}
function clearSession(res) { res.clearCookie("session", sessionCookieOptions()); }
async function getCurrentUser(req) {
  const token = req.cookies.session || "";
  const session = verifySession(token);
  if (!session?.userId) return null;
  return prisma.user.findUnique({ where: { id: session.userId } });
}
function isAdmin(user) { return !!user && user.role === "admin"; }
async function authRequired(req, res, next) {
  const user = await getCurrentUser(req);
  if (!user) return res.redirect("/login");
  req.user = user;
  next();
}
async function adminRequired(req, res, next) {
  const user = await getCurrentUser(req);
  if (!isAdmin(user)) return res.redirect("/login?error=Kein+Adminzugriff");
  req.user = user;
  next();
}
function renderFlash(req) {
  const success = req.query.success ? `<div class="alert success">${escapeHtml(req.query.success)}</div>` : "";
  const error = req.query.error ? `<div class="alert error">${escapeHtml(req.query.error)}</div>` : "";
  return success + error;
}
function brandLogoMarkup() {
  if (!fs.existsSync(brandLogoPath)) return "🍕";
  return `<img src="/brand-logo" alt="${escapeHtml(BRAND_NAME)} Logo" class="brand-logo-img" />`;
}
function nav(user) {
  if (!user) return `<a href="/login">Login</a><a href="/register">Mitglied werden</a>`;
  return `
    <a href="/account">Konto</a>
    <a href="/wallet">Wallet</a>
    ${isAdmin(user) ? `<a href="/admin">Admin</a>` : ""}
    <form method="post" action="/logout" class="inline-nav"><button type="submit" class="linklike">Logout</button></form>
  `;
}
function page({ title, user, body, description = "", head = "", pageClass = "" }) {
  return `<!doctype html>
  <html lang="de">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>${escapeHtml(title)} · ${escapeHtml(BRAND_NAME)}</title>
    <meta name="theme-color" content="#b35b2f" />
    <meta name="description" content="${escapeHtml(description || BRAND_SUBTITLE)}" />
    <link rel="stylesheet" href="/static/styles.css" />
    <style>
      :root{--bg:#f7f2ed;--surface:#fff;--surface-soft:#fff8f2;--text:#211711;--muted:#6c6158;--line:rgba(117,85,58,.16);--accent:#b35b2f;--accent-dark:#8f451f;--success:#1f7650;--danger:#b54141;--radius:24px;--shadow:0 16px 40px rgba(40,24,14,.06)}
      *{box-sizing:border-box} html,body{margin:0;padding:0} body{font-family:Inter,system-ui,sans-serif;background:radial-gradient(circle at top left,rgba(179,91,47,.06),transparent 20%),var(--bg);color:var(--text)}
      .app-shell{width:min(1180px,calc(100% - 24px));margin:0 auto;padding:16px 0 30px}
      .topbar{position:sticky;top:10px;z-index:30;display:flex;align-items:center;justify-content:space-between;gap:18px;padding:14px;border-radius:24px;background:rgba(255,250,246,.88);border:1px solid var(--line);backdrop-filter:blur(12px)}
      .brand{display:flex;align-items:center;gap:14px}.brand-icon{width:68px;height:68px;border-radius:20px;background:#fff6ee;border:1px solid rgba(179,91,47,.12);display:grid;place-items:center;padding:8px;overflow:hidden;flex:0 0 auto}.brand-logo-img{max-height:48px;max-width:100%;object-fit:contain}
      .brand-title{font-size:clamp(20px,2.2vw,30px);font-weight:800;letter-spacing:-.03em;line-height:1}.brand-subtitle{margin-top:4px;color:var(--muted);font-size:14px}
      .topnav,.inline-nav,.button-row,.inline-form{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
      .topnav a,.linklike{display:inline-flex;align-items:center;justify-content:center;min-height:42px;padding:10px 14px;border-radius:999px;text-decoration:none;color:var(--text);font-weight:700;border:1px solid transparent;background:transparent}
      .topnav a:hover,.linklike:hover{background:#fff;border-color:var(--line)}
      .page{display:grid;gap:18px;margin-top:18px}.page-head h1{margin:0;font-size:clamp(32px,4vw,44px);letter-spacing:-.04em}.page-head p{margin:6px 0 0;color:var(--muted)}
      .card{background:linear-gradient(180deg,#fff 0%,#fffaf6 100%);border:1px solid var(--line);border-radius:var(--radius);padding:22px;box-shadow:var(--shadow)}
      .eyebrow,.pill{display:inline-flex;align-items:center;gap:8px;width:max-content;padding:8px 12px;border-radius:999px;background:#fff1e7;color:var(--accent-dark);font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}
      .grid.two{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.grid.three{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px}.stat-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
      .section-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-end;margin-bottom:14px}.section-head h2,.section-head h3{margin:0}.section-head p{margin:0;color:var(--muted)}
      .btn{appearance:none;border:none;display:inline-flex;align-items:center;justify-content:center;min-height:48px;padding:12px 16px;border-radius:16px;text-decoration:none;font-weight:800;cursor:pointer}
      .btn-primary{background:linear-gradient(180deg,#c86d3e 0%,#a9542a 100%);color:#fff}.btn-secondary{background:#fff;border:1px solid var(--line);color:var(--text)}.btn-ghost{background:#fff5ec;border:1px solid rgba(179,91,47,.14);color:var(--accent-dark)}
      .btn:disabled{opacity:.55;cursor:not-allowed}.muted{color:var(--muted)}
      label{display:grid;gap:8px;font-size:14px;font-weight:700;color:#3d3128} input,textarea,select{width:100%;min-height:48px;border:1px solid rgba(117,85,58,.24);border-radius:14px;padding:12px 14px;font:inherit;background:#fff;color:var(--text)} input:focus,textarea:focus,select:focus{outline:none;border-color:rgba(179,91,47,.45);box-shadow:0 0 0 4px rgba(179,91,47,.12)} form{display:grid;gap:14px}
      .alert{padding:14px 16px;border-radius:16px;font-weight:700}.success{background:#edf8f2;color:var(--success);border:1px solid rgba(31,118,80,.16)}.error{background:#fff3f3;color:var(--danger);border:1px solid rgba(181,65,65,.16)}
      .status-line{padding:12px 14px;border-radius:16px;background:var(--surface-soft);border:1px solid var(--line);color:var(--muted)}
      .event-list,.task-list,.voucher-list,.identity-list{display:grid;gap:12px}.event-row,.task-card,.voucher-item,.identity-row{padding:16px;border-radius:18px;border:1px solid var(--line);background:linear-gradient(180deg,#fffaf6 0%,#fff 100%)}
      .event-row,.voucher-item,.identity-row{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.event-row strong,.task-card strong,.voucher-item strong,.identity-row strong{display:block;margin-bottom:4px}.event-row small,.task-card p,.voucher-item small{color:var(--muted);margin:0}.event-side{font-weight:800;white-space:nowrap}
      .hero{display:grid;grid-template-columns:minmax(0,1fr) minmax(220px,260px);gap:18px;align-items:center;padding:24px;background:linear-gradient(135deg,#fff8f2 0%,#fffdf9 100%)}
      .hero h2{margin:8px 0;font-size:clamp(30px,4vw,42px);letter-spacing:-.05em;line-height:1}.hero p{margin:0;color:var(--muted)}.hero-qr{background:#fff;border:1px solid var(--line);border-radius:22px;padding:12px;display:grid;justify-items:center}
      .stats-card{padding:16px;border-radius:18px;background:#fff;border:1px solid var(--line)} .stats-card strong{display:block;font-size:28px;line-height:1;margin-bottom:6px} .stats-card span{color:var(--muted);font-size:14px}
      .reward-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.reward-card{padding:16px;border-radius:18px;border:1px solid var(--line);background:#fffaf6;display:grid;gap:12px}.reward-open{background:linear-gradient(180deg,#f5fff9 0%,#fffdfb 100%);border-color:rgba(31,118,80,.18)}
      .reward-top,.task-top{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.reward-cost,.task-badge{display:inline-flex;align-items:center;justify-content:center;padding:8px 10px;border-radius:999px;font-size:13px;font-weight:800}
      .reward-cost{background:#fff;border:1px solid var(--line)} .task-badge.idle{background:#fff1e7;color:var(--accent-dark)} .task-badge.pending{background:#eef4ff;color:#355f9d} .task-badge.rejected{background:#fff1f1;color:#af4c4c}
      .qr-image{width:min(260px,100%);border-radius:20px;background:#fff;padding:8px;border:1px solid var(--line)}
      .voucher-code{font-family:ui-monospace,monospace}
      .reader{min-height:320px;border-radius:20px;background:linear-gradient(180deg,rgba(179,91,47,.03),rgba(255,255,255,.6)),#fffaf6;border:1px dashed rgba(179,91,47,.22);overflow:hidden}
      .tabbar{position:sticky;top:96px;z-index:15;padding:12px;border-radius:22px;background:rgba(255,250,246,.88);border:1px solid var(--line);backdrop-filter:blur(10px)} .tabbar .button-row{gap:10px}
      .table-wrap{overflow:auto;border:1px solid var(--line);border-radius:18px} table{width:100%;border-collapse:collapse} th,td{padding:14px;border-bottom:1px solid rgba(117,85,58,.12);text-align:left;vertical-align:top} th{font-size:13px;color:var(--muted)} td small{display:block;margin-top:4px;color:var(--muted)}
      .page-footer{margin-top:22px;padding:16px 4px 8px;text-align:center;color:var(--muted);font-size:14px}
      .page-footer a{color:var(--accent-dark);font-weight:800;text-decoration:none}
      @media (max-width:960px){.grid.two,.grid.three,.stat-grid,.reward-grid,.hero{grid-template-columns:1fr}.section-head,.event-row,.voucher-item,.identity-row,.reward-top,.task-top{flex-direction:column;align-items:flex-start}.event-side{white-space:normal}}
      @media (max-width:760px){.app-shell{width:min(100%,calc(100% - 16px));padding-top:10px}.topbar{top:8px;flex-direction:column;align-items:flex-start;border-radius:22px}.topnav{width:100%;justify-content:flex-start}.brand-icon{width:60px;height:60px}.brand-logo-img{max-height:42px}.card{padding:18px}.button-row,.inline-form,.inline-nav{flex-direction:column;align-items:stretch}.tabbar{top:84px}}
    </style>
    ${head}
  </head>
  <body class="${escapeHtml(pageClass)}">
    <div class="app-shell">
      <header class="topbar">
        <div class="brand">
          <div class="brand-icon">${brandLogoMarkup()}</div>
          <div><div class="brand-title">${escapeHtml(BRAND_NAME)}</div><div class="brand-subtitle">${escapeHtml(BRAND_SUBTITLE)}</div></div>
        </div>
        <nav class="topnav">${nav(user)}</nav>
      </header>
      <main class="page">
        ${description ? `<section class="page-head"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(description)}</p></section>` : ""}
        ${body}
      </main>
      <footer class="page-footer">Kundenkarte, Rewards & Vorteile · <a href="https://www.pizza-berlino.de/" target="_blank" rel="noreferrer">${escapeHtml(BRAND_NAME)}</a></footer>
    </div>
  </body>
  </html>`;
}
function resolveRewardAvailability(user) {
  return rewardDefs.map(reward => ({ ...reward, canRedeem: user.points >= reward.cost }));
}
function nextRewardProgress(points) {
  const nextReward = rewardDefs.find(r => points < r.cost) || rewardDefs[rewardDefs.length - 1];
  return { nextReward, remaining: Math.max(0, nextReward.cost - points) };
}
function nextPizzaProgress(pizzaCount, hasVoucher) {
  const filled = hasVoucher ? 10 : Math.max(0, Number(pizzaCount || 0)) % 10;
  return { filled, remaining: hasVoucher ? 0 : 10 - filled };
}
function formatEventSide(event) {
  const parts = [];
  if (event.points) parts.push(`${event.points > 0 ? "+" : ""}${event.points} Pkt`);
  if (event.pizzas) parts.push(`${event.pizzas > 0 ? "+" : ""}${event.pizzas} Pizza`);
  return parts.join(" · ") || "–";
}
function scannerConfigSummary(cfg) {
  return `${cfg.label} · +${cfg.addPoints} Punkte · +${cfg.addPizzas} Pizzen${cfg.oncePerDay ? " · 1x täglich" : ""}`;
}
function submissionLabel(s) {
  if (s.type === "review") return "Google Bewertung";
  if (s.type === "tiktok") return "TikTok Beitrag";
  if (s.type === "custom") return s.note || "Aktion";
  return s.type;
}
function taskBadge(status, fallback = "Offen") {
  if (status === "pending") return { text: "Wird geprüft", cls: "pending" };
  if (status === "rejected") return { text: "Erneut senden", cls: "rejected" };
  return { text: fallback, cls: "idle" };
}

async function ensureScannerConfig() {
  return prisma.scannerConfig.upsert({
    where: { id: 1 },
    update: {},
    create: { id: 1, active: true, label: "2 Pizzen bestellt", addPoints: 15, addPizzas: 2, oncePerDay: true }
  });
}
async function getTaskState(userId, type) {
  return prisma.taskState.upsert({
    where: { userId_type: { userId, type } },
    update: {},
    create: { id: uid(), userId, type, clickedAt: null, claimedAt: null, status: "idle" }
  });
}
async function getOpenVouchers(userId) {
  return prisma.voucher.findMany({ where: { userId, status: "open" }, orderBy: { createdAt: "desc" } });
}
async function getUserEvents(userId, take = 12) {
  return prisma.event.findMany({ where: { userId }, orderBy: { createdAt: "desc" }, take });
}
async function latestSubmission(userId, type, taskId = null) {
  return prisma.submission.findFirst({ where: { userId, type, ...(taskId ? { taskId } : {}) }, orderBy: { createdAt: "desc" } });
}
async function pendingSubmission(userId, type, taskId = null) {
  return prisma.submission.findFirst({ where: { userId, type, status: "pending", ...(taskId ? { taskId } : {}) } });
}
async function memberQrDataUrl(user) {
  return QRCode.toDataURL(`lpw:${user.walletToken}`, { margin: 1, width: 260 });
}
async function createVoucher(userId, title, source, meta = {}, tx = prisma) {
  const code = `PB-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
  return tx.voucher.create({ data: { id: uid(), userId, title, source, code, status: "open", createdAt: nowDate(), usedAt: null, usedBy: null, meta } });
}
async function addEvent(userId, type, points, pizzas, note, meta = {}, tx = prisma) {
  const user = await tx.user.findUnique({ where: { id: userId } });
  if (!user) throw new Error("USER_NOT_FOUND");
  const nextPoints = Math.max(0, Number(user.points || 0) + Number(points || 0));
  const nextPizzaCount = Math.max(0, Number(user.pizzaCount || 0) + Number(pizzas || 0));
  await tx.user.update({ where: { id: userId }, data: { points: nextPoints, pizzaCount: nextPizzaCount } });
  const event = await tx.event.create({ data: { id: uid(), userId, type, points: Number(points || 0), pizzas: Number(pizzas || 0), note, meta, createdAt: nowDate(), dayKey: dayKey() } });
  if (Number(pizzas || 0) > 0) {
    const before = Math.floor(Number(user.pizzaCount || 0) / 10);
    const after = Math.floor(nextPizzaCount / 10);
    for (let i = before + 1; i <= after; i += 1) {
      await createVoucher(userId, "Kostenlose Pizza", "pizza-milestone", { milestone: i * 10 }, tx);
      await tx.event.create({ data: { id: uid(), userId, type: "pizza-milestone", points: 0, pizzas: 0, note: `Gratis-Pizza für ${i * 10} Pizzen freigeschaltet`, meta: { milestone: i * 10 }, createdAt: nowDate(), dayKey: dayKey() } });
    }
  }
  return event;
}
async function findUserByWalletPayload(payload) {
  if (!payload.startsWith("lpw:")) return null;
  return prisma.user.findUnique({ where: { walletToken: payload.replace(/^lpw:/, "") } });
}
function assertStaffPin(pin) { return safeEqual(String(pin || "").trim(), STAFF_PIN); }
async function hasCustomScanAlreadyRun(userId, configHash) {
  const events = await prisma.event.findMany({ where: { userId, type: "staff-scan", dayKey: dayKey() } });
  return events.some(event => event?.meta?.configHash === configHash);
}

function assertResendConfigured() {
  if (!RESEND_API_KEY || !process.env.SMTP_FROM) throw new Error("RESEND_NOT_CONFIGURED");
}
async function verifyMailerConnection() {
  try {
    assertResendConfigured();
    console.log("Resend API configured");
  } catch (error) {
    console.error("Resend config check failed", error);
  }
}
async function sendVerificationMail(user, verifyLink) {
  assertResendConfigured();
  const { error } = await resend.emails.send({
    from: process.env.SMTP_FROM,
    to: [user.email],
    subject: `${BRAND_NAME} – E-Mail bestätigen`,
    html: `<div style="font-family:Inter,Arial,sans-serif;line-height:1.5;color:#241c16;max-width:580px;margin:0 auto;padding:24px">
      <div style="font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#b35b2f;margin-bottom:8px">${escapeHtml(BRAND_SUBTITLE)}</div>
      <h1 style="margin:0 0 12px;font-size:28px;line-height:1.1">Willkommen bei ${escapeHtml(BRAND_NAME)}</h1>
      <p style="margin:0 0 12px">Hallo ${escapeHtml(user.name)},</p>
      <p style="margin:0 0 20px">bitte bestätige deine E-Mail-Adresse, damit dein Konto aktiviert wird.</p>
      <p style="margin:0 0 20px"><a href="${verifyLink}" style="display:inline-block;padding:12px 16px;background:#b35b2f;color:#fff;text-decoration:none;border-radius:12px;font-weight:700">E-Mail bestätigen</a></p>
      <p style="margin:0;color:#6d6258;word-break:break-all">${escapeHtml(verifyLink)}</p>
    </div>`
  });
  if (error) throw error;
}
async function sendPasswordResetMail(user, resetLink) {
  assertResendConfigured();
  const { error } = await resend.emails.send({
    from: process.env.SMTP_FROM,
    to: [user.email],
    subject: `${BRAND_NAME} – Passwort zurücksetzen`,
    html: `<div style="font-family:Inter,Arial,sans-serif;line-height:1.5;color:#241c16;max-width:580px;margin:0 auto;padding:24px">
      <div style="font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#b35b2f;margin-bottom:8px">${escapeHtml(BRAND_SUBTITLE)}</div>
      <h1 style="margin:0 0 12px;font-size:28px;line-height:1.1">Passwort zurücksetzen</h1>
      <p style="margin:0 0 12px">Hallo ${escapeHtml(user.name)},</p>
      <p style="margin:0 0 20px">Mit dem Button unten kannst du ein neues Passwort festlegen.</p>
      <p style="margin:0 0 20px"><a href="${resetLink}" style="display:inline-block;padding:12px 16px;background:#b35b2f;color:#fff;text-decoration:none;border-radius:12px;font-weight:700">Neues Passwort festlegen</a></p>
      <p style="margin:0;color:#6d6258;word-break:break-all">${escapeHtml(resetLink)}</p>
    </div>`
  });
  if (error) throw error;
}

app.get("/", async (req, res) => {
  const user = await getCurrentUser(req);
  if (user) return res.redirect("/account");
  const body = `
    <section class="card" style="min-height:460px;display:grid;align-content:center;justify-items:center;text-align:center;background:radial-gradient(circle at top,rgba(179,91,47,.12),transparent 40%),linear-gradient(135deg,#fff8f2 0%,#fffdf9 100%)">
      <div class="eyebrow">Pizza Loyalty</div>
      <h2 style="margin:0;max-width:14ch;font-size:clamp(40px,6vw,68px);line-height:.98;letter-spacing:-.05em">Das Loyalty-Programm für echte Stammkunden.</h2>
      <p style="margin:0;max-width:58ch;color:var(--muted);font-size:18px">Punkte sammeln, Rewards nutzen und deine digitale Kundenkarte immer griffbereit haben – schnell, mobil und professionell.</p>
      <div class="button-row">
        <a class="btn btn-primary" href="/register">Mitglied werden</a>
        <a class="btn btn-secondary" href="/login">Einloggen</a>
      </div>
    </section>
  `;
  res.send(page({ title: "Willkommen", user, body, description: "Das digitale Loyalty-Programm von Pizza Berlino." }));
});

app.get("/register", async (req, res) => {
  const user = await getCurrentUser(req);
  if (user) return res.redirect("/account");
  const pendingEmail = String(req.query.email || "").trim().toLowerCase();
  const showVerificationState = !!pendingEmail && !!req.query.success;

  const body = showVerificationState ? `
    ${renderFlash(req)}
    <section style="display:flex;justify-content:center">
      <div class="card" style="width:min(100%,640px)">
        <div class="eyebrow">E-Mail bestätigen</div>
        <h2 style="margin:12px 0 8px">Bestätigungslink gesendet</h2>
        <div class="pill" style="text-transform:none;letter-spacing:0">${escapeHtml(pendingEmail)}</div>
        <p class="muted" style="margin:14px 0 0">Bitte bestätige deine E-Mail-Adresse und logge dich danach ein.</p>
        <div class="button-row" style="margin-top:18px"><a class="btn btn-secondary" href="/login">Zum Login</a></div>
        <div id="resendHint" class="muted" style="margin-top:16px;font-size:13px" hidden>Noch nichts angekommen? <button type="button" id="toggleResendPanel" class="linklike" style="padding:0;min-height:auto">Link erneut senden</button></div>
        <form id="resendPanel" method="post" action="/resend-verification" hidden style="margin-top:12px;padding:14px;border-radius:18px;background:var(--surface-soft);border:1px solid var(--line)">
          <input type="hidden" name="email" value="${escapeHtml(pendingEmail)}" />
          <button class="btn btn-primary" type="submit">Neuen Link senden</button>
        </form>
      </div>
    </section>
    <script>
      const hint=document.getElementById("resendHint");
      const panel=document.getElementById("resendPanel");
      document.getElementById("toggleResendPanel")?.addEventListener("click",()=>{ panel.hidden=!panel.hidden; });
      window.setTimeout(()=>{ if(hint) hint.hidden=false; }, 4000);
    </script>
  ` : `
    ${renderFlash(req)}
    <section style="display:flex;justify-content:center">
      <form class="card" style="width:min(100%,640px)" method="post" action="/register">
        <div class="eyebrow">Neues Kundenkonto</div>
        <h2 style="margin:12px 0 8px">Mitglied werden</h2>
        <p class="muted" style="margin:0">Digital sammeln, im Laden scannen und Vorteile direkt nutzen.</p>
        <label>Name<input name="name" required maxlength="80" placeholder="Valentina Rossi" autocomplete="name" /></label>
        <label>E-Mail<input type="email" name="email" required maxlength="120" placeholder="kunde@beispiel.de" autocomplete="email" /></label>
        <label>Passwort<input type="password" name="password" required minlength="10" placeholder="${escapeHtml(passwordPolicyHint())}" autocomplete="new-password" /></label>
        <div class="status-line">${escapeHtml(passwordPolicyHint())}</div>
        <button class="btn btn-primary" type="submit">Konto erstellen</button>
      </form>
    </section>
  `;
  res.send(page({ title: "Mitglied werden", user, body, description: "Erstelle dein Pizza-Berlino-Konto." }));
});

app.post("/register", rateLimit({ windowMs: 15 * 60 * 1000, max: 20, store: authRateStore, name: "register" }), async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const pw = validatePassword(password, email, name);
  if (!name || !email || !pw.valid) return res.redirect(`/register?error=${encodeURIComponent(name && email ? pw.message : "Bitte alle Felder korrekt ausfüllen")}`);

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing?.verified) return res.redirect("/register?error=E-Mail+bereits+registriert");

  const passwordHash = await bcrypt.hash(password, 12);
  const verifyToken = DEV_AUTO_VERIFY ? null : uid();

  const user = existing && !existing.verified
    ? await prisma.user.update({ where: { id: existing.id }, data: { name, passwordHash, role: ADMIN_EMAILS.has(email) ? "admin" : existing.role, verified: DEV_AUTO_VERIFY, verifyToken } })
    : await prisma.user.create({ data: { id: uid(), name, email, passwordHash, role: ADMIN_EMAILS.has(email) ? "admin" : "customer", verified: DEV_AUTO_VERIFY, verifyToken, walletToken: `member_${crypto.randomBytes(10).toString("hex")}`, points: 0, pizzaCount: 0, createdAt: nowDate() } });

  if (DEV_AUTO_VERIFY) return res.redirect("/login?success=Konto+erstellt.+Du+kannst+dich+jetzt+einloggen");

  try {
    await sendVerificationMail(user, absoluteUrl(`/verify?token=${encodeURIComponent(verifyToken)}`));
    return res.redirect(`/register?success=Bestätigungslink+gesendet&email=${encodeURIComponent(email)}`);
  } catch (error) {
    console.error("Verification mail failed", error);
    return res.redirect(`/register?error=Bestätigungsmail+konnte+nicht+gesendet+werden&email=${encodeURIComponent(email)}`);
  }
});

app.post("/resend-verification", rateLimit({ windowMs: 10 * 60 * 1000, max: 6, store: authRateStore, name: "resend-verification" }), async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!email) return res.redirect("/register?error=Bitte+eine+E-Mail-Adresse+eingeben");
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.redirect(`/register?error=Konto+nicht+gefunden&email=${encodeURIComponent(email)}`);
  if (user.verified) return res.redirect(`/register?success=Diese+E-Mail+ist+bereits+bestätigt&email=${encodeURIComponent(email)}`);
  const verifyToken = uid();
  const updated = await prisma.user.update({ where: { id: user.id }, data: { verifyToken } });
  try {
    await sendVerificationMail(updated, absoluteUrl(`/verify?token=${encodeURIComponent(verifyToken)}`));
    res.redirect(`/register?success=Neuer+Bestätigungslink+gesendet&email=${encodeURIComponent(email)}`);
  } catch (error) {
    console.error("Resend verification mail failed", error);
    res.redirect(`/register?error=Mail+konnte+nicht+gesendet+werden&email=${encodeURIComponent(email)}`);
  }
});

app.get("/verify", async (req, res) => {
  const token = String(req.query.token || "").trim();
  const user = await prisma.user.findFirst({ where: { verifyToken: token } });
  if (!user) return res.redirect("/login?error=Ungültiger+Bestätigungslink");
  await prisma.user.update({ where: { id: user.id }, data: { verified: true, verifyToken: null } });
  res.redirect("/login?success=E-Mail+bestätigt.+Du+kannst+dich+jetzt+einloggen");
});

app.get("/login", async (req, res) => {
  const user = await getCurrentUser(req);
  if (user) return res.redirect("/account");
  const body = `
    ${renderFlash(req)}
    <section style="display:flex;justify-content:center">
      <div class="card" style="width:min(100%,560px)">
        <div class="eyebrow">Login</div>
        <h2 style="margin:12px 0 8px">Willkommen zurück</h2>
        <p class="muted" style="margin:0">Melde dich mit deinem Pizza-Berlino-Konto an.</p>
        <form method="post" action="/login">
          <label>E-Mail<input type="email" name="email" required placeholder="kunde@beispiel.de" autocomplete="email" /></label>
          <label>Passwort<input type="password" name="password" required autocomplete="current-password" /></label>
          <div style="display:flex;justify-content:flex-end;margin-top:-4px"><a href="/forgot-password" style="text-decoration:none;color:var(--accent-dark);font-weight:800">Passwort vergessen?</a></div>
          <button class="btn btn-primary" type="submit">Einloggen</button>
        </form>
        <p class="muted" style="margin:4px 0 0">Noch kein Konto? <a href="/register" style="text-decoration:none;color:var(--accent-dark);font-weight:800">Mitglied werden</a></p>
      </div>
    </section>
  `;
  res.send(page({ title: "Login", user, body, description: "Mit deinem Pizza-Berlino-Konto anmelden." }));
});

app.post("/login", rateLimit({ windowMs: 15 * 60 * 1000, max: 15, store: authRateStore, name: "login" }), async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.redirect("/login?error=Konto+nicht+gefunden");
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.redirect("/login?error=Falsches+Passwort");
  if (!user.verified) return res.redirect("/login?error=Bitte+erst+deine+E-Mail+bestätigen");
  setSession(res, user);
  res.redirect("/account");
});

app.get("/forgot-password", async (req, res) => {
  const user = await getCurrentUser(req);
  const body = `
    ${renderFlash(req)}
    <section class="grid two">
      <form class="card" method="post" action="/forgot-password">
        <div class="eyebrow">Reset</div>
        <h2 style="margin:12px 0 8px">Passwort vergessen</h2>
        <p class="muted" style="margin:0">Wir senden dir einen Link zum Zurücksetzen.</p>
        <label>E-Mail<input type="email" name="email" required placeholder="kunde@beispiel.de" autocomplete="email" /></label>
        <button class="btn btn-primary" type="submit">Reset-Link senden</button>
      </form>
      <div class="card">
        <h3 style="margin:0 0 8px">Schnell zurück</h3>
        <p class="muted" style="margin:0 0 16px">Du kannst danach direkt wieder einloggen.</p>
        <div class="button-row">
          <a class="btn btn-secondary" href="/login">Zum Login</a>
          ${user ? `<a class="btn btn-ghost" href="/account">Zum Konto</a>` : `<a class="btn btn-ghost" href="/register">Neu registrieren</a>`}
        </div>
      </div>
    </section>
  `;
  res.send(page({ title: "Passwort vergessen", user, body, description: "Link anfordern und neues Passwort setzen." }));
});

app.post("/forgot-password", rateLimit({ windowMs: 15 * 60 * 1000, max: 10, store: authRateStore, name: "forgot-password" }), async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!email) return res.redirect("/forgot-password?error=Bitte+eine+E-Mail-Adresse+eingeben");

  try { assertResendConfigured(); } catch { return res.redirect("/forgot-password?error=Reset-Mail+aktuell+nicht+verfügbar"); }

  const user = await prisma.user.findUnique({ where: { email } });
  if (user?.verified) {
    const token = signTimedToken({ purpose: "password-reset", userId: user.id, email: user.email, fp: passwordResetFingerprint(user) }, PASSWORD_RESET_EXPIRES_MINUTES);
    try { await sendPasswordResetMail(user, absoluteUrl(`/reset-password?token=${encodeURIComponent(token)}`)); } catch (error) { console.error("Password reset mail failed", error); }
  }
  res.redirect("/forgot-password?success=Wenn+ein+Konto+existiert,+wurde+eine+Mail+gesendet");
});

app.get("/reset-password", async (req, res) => {
  const user = await getCurrentUser(req);
  const token = String(req.query.token || "").trim();
  const payload = verifyTimedToken(token, "password-reset");
  if (!payload?.userId || !payload?.email || !payload?.fp) return res.redirect("/forgot-password?error=Reset-Link+ungültig+oder+abgelaufen");
  const resetUser = await prisma.user.findUnique({ where: { id: payload.userId } });
  if (!resetUser || resetUser.email !== payload.email || passwordResetFingerprint(resetUser) !== payload.fp) {
    return res.redirect("/forgot-password?error=Reset-Link+ungültig+oder+abgelaufen");
  }

  const body = `
    ${renderFlash(req)}
    <section class="grid two">
      <form class="card" method="post" action="/reset-password">
        <div class="eyebrow">Neues Passwort</div>
        <h2 style="margin:12px 0 8px">Passwort zurücksetzen</h2>
        <p class="muted" style="margin:0">${escapeHtml(passwordPolicyHint())}</p>
        <input type="hidden" name="token" value="${escapeHtml(token)}" />
        <label>Neues Passwort<input type="password" name="password" minlength="10" required autocomplete="new-password" /></label>
        <label>Passwort wiederholen<input type="password" name="passwordConfirm" minlength="10" required autocomplete="new-password" /></label>
        <button class="btn btn-primary" type="submit">Passwort speichern</button>
      </form>
      <div class="card">
        <h3 style="margin:0 0 8px">${escapeHtml(resetUser.email)}</h3>
        <div class="status-line">${escapeHtml(passwordPolicyHint())}</div>
      </div>
    </section>
  `;
  res.send(page({ title: "Passwort zurücksetzen", user, body, description: "Neues Passwort festlegen." }));
});

app.post("/reset-password", rateLimit({ windowMs: 15 * 60 * 1000, max: 12, store: authRateStore, name: "reset-password" }), async (req, res) => {
  const token = String(req.body.token || "").trim();
  const password = String(req.body.password || "");
  const passwordConfirm = String(req.body.passwordConfirm || "");
  const payload = verifyTimedToken(token, "password-reset");
  if (!payload?.userId || !payload?.email || !payload?.fp) return res.redirect("/forgot-password?error=Reset-Link+ungültig+oder+abgelaufen");
  if (password !== passwordConfirm) return res.redirect(`/reset-password?token=${encodeURIComponent(token)}&error=Passwörter+stimmen+nicht+überein`);
  const user = await prisma.user.findUnique({ where: { id: payload.userId } });
  if (!user || user.email !== payload.email || passwordResetFingerprint(user) !== payload.fp) return res.redirect("/forgot-password?error=Reset-Link+ungültig+oder+abgelaufen");
  const pw = validatePassword(password, user.email, user.name);
  if (!pw.valid) return res.redirect(`/reset-password?token=${encodeURIComponent(token)}&error=${encodeURIComponent(pw.message)}`);
  if (await bcrypt.compare(password, user.passwordHash)) return res.redirect(`/reset-password?token=${encodeURIComponent(token)}&error=Bitte+ein+neues+Passwort+verwenden`);
  await prisma.user.update({ where: { id: user.id }, data: { passwordHash: await bcrypt.hash(password, 12) } });
  res.redirect("/login?success=Passwort+aktualisiert.+Du+kannst+dich+jetzt+einloggen");
});

app.post("/logout", (req, res) => {
  clearSession(res);
  res.redirect("/login?success=Abgemeldet");
});

app.get("/account", authRequired, async (req, res) => {
  const user = req.user;
  const [qr, vouchers, events, instagramTask, reviewSubmission, tiktokSubmission, customTasks] = await Promise.all([
    memberQrDataUrl(user),
    getOpenVouchers(user.id),
    getUserEvents(user.id, 12),
    getTaskState(user.id, "instagram"),
    latestSubmission(user.id, "review"),
    latestSubmission(user.id, "tiktok"),
    prisma.customTask.findMany({ where: { active: true }, orderBy: { createdAt: "desc" } })
  ]);

  const rewardProgress = nextRewardProgress(user.points);
  const pizzaVoucher = vouchers.find(v => v.source === "pizza-milestone");
  const pizzaProgress = nextPizzaProgress(user.pizzaCount, Boolean(pizzaVoucher));
  const rewards = resolveRewardAvailability(user);
  const customTaskSubmissions = await Promise.all(customTasks.map(task => latestSubmission(user.id, "custom", task.id)));
  const firstName = String(user.name || "").trim().split(/\s+/)[0] || user.name;

  const actionCards = [];
  if (!instagramTask.claimedAt) {
    actionCards.push(`
      <div class="task-card">
        <div class="task-top">
          <div><strong>Instagram folgen</strong><p>Profil direkt öffnen – die Gutschrift läuft im Hintergrund.</p></div>
          <span class="task-badge idle">25 Pkt</span>
        </div>
        <div class="button-row"><a class="btn btn-primary js-instagram-task" href="${escapeHtml(INSTAGRAM_URL)}" target="_blank" rel="noreferrer">Instagram öffnen</a></div>
      </div>
    `);
  }
  if (reviewSubmission?.status !== "approved") {
    const badge = taskBadge(reviewSubmission?.status, "Review");
    actionCards.push(`
      <div class="task-card">
        <div class="task-top">
          <div><strong>Google Bewertung</strong><p>Bewertung abgeben und den Link danach einreichen.</p></div>
          <span class="task-badge ${badge.cls}">${badge.text}</span>
        </div>
        ${reviewSubmission?.link ? `<a href="${escapeHtml(reviewSubmission.link)}" target="_blank" rel="noreferrer" style="text-decoration:none;color:var(--accent-dark);font-weight:800">Bisherigen Nachweis ansehen</a>` : ""}
        <div class="button-row"><a class="btn btn-ghost" href="${escapeHtml(REVIEW_URL)}" target="_blank" rel="noreferrer">Google öffnen</a></div>
        ${reviewSubmission?.status === "pending" ? "" : `<form class="inline-form" method="post" action="/tasks/review/submit"><input name="link" placeholder="Dein Bewertungs- oder Profil-Link" required /><button class="btn btn-secondary" type="submit">${reviewSubmission?.status === "rejected" ? "Erneut senden" : "Link senden"}</button></form>`}
      </div>
    `);
  }
  if (tiktokSubmission?.status !== "approved") {
    const badge = taskBadge(tiktokSubmission?.status, "50 Pkt");
    actionCards.push(`
      <div class="task-card">
        <div class="task-top">
          <div><strong>TikTok Beitrag</strong><p>Link einreichen, danach prüft das Team deinen Beitrag.</p></div>
          <span class="task-badge ${badge.cls}">${badge.text}</span>
        </div>
        ${tiktokSubmission?.link ? `<a href="${escapeHtml(tiktokSubmission.link)}" target="_blank" rel="noreferrer" style="text-decoration:none;color:var(--accent-dark);font-weight:800">Bisherigen Nachweis ansehen</a>` : ""}
        ${tiktokSubmission?.status === "pending" ? "" : `<form class="inline-form" method="post" action="/tasks/tiktok"><input name="link" placeholder="https://www.tiktok.com/..." required /><button class="btn btn-secondary" type="submit">${tiktokSubmission?.status === "rejected" ? "Erneut senden" : "Einreichen"}</button></form>`}
      </div>
    `);
  }
  customTasks.forEach((task, index) => {
    const submission = customTaskSubmissions[index];
    if (submission?.status === "approved") return;
    const badge = taskBadge(submission?.status, `${task.points} Pkt`);
    actionCards.push(`
      <div class="task-card">
        <div class="task-top">
          <div><strong>${escapeHtml(task.title)}</strong><p>${escapeHtml(task.description)}</p></div>
          <span class="task-badge ${badge.cls}">${badge.text}</span>
        </div>
        ${submission?.link ? `<a href="${escapeHtml(submission.link)}" target="_blank" rel="noreferrer" style="text-decoration:none;color:var(--accent-dark);font-weight:800">Bisherigen Nachweis ansehen</a>` : ""}
        ${task.targetUrl ? `<div class="button-row"><a class="btn btn-ghost" href="${escapeHtml(task.targetUrl)}" target="_blank" rel="noreferrer">Aktion öffnen</a></div>` : ""}
        ${submission?.status === "pending" ? "" : `<form class="inline-form" method="post" action="/tasks/custom/${task.id}/submit"><input name="link" placeholder="Dein Link oder Nachweis" required /><button class="btn btn-secondary" type="submit">${submission?.status === "rejected" ? "Erneut senden" : "Einreichen"}</button></form>`}
      </div>
    `);
  });

  const body = `
    ${renderFlash(req)}
    <section class="card hero">
      <div>
        <div class="eyebrow">Hi ${escapeHtml(firstName)}</div>
        <h2>Dein Loyalty-Konto</h2>
        <p>${escapeHtml(rewardProgress.remaining === 0 ? `${rewardProgress.nextReward.title} ist bereit.` : `${rewardProgress.remaining} Punkte bis ${rewardProgress.nextReward.title}.`)}</p>
      </div>
      <div class="hero-qr">
        <img class="qr-image" src="${qr}" alt="Member QR" />
        <div class="muted" style="font-size:13px;margin-top:8px">Im Laden einfach scannen lassen.</div>
      </div>
    </section>

    <section class="stat-grid">
      <div class="stats-card"><strong>${user.points}</strong><span>Punkte</span></div>
      <div class="stats-card"><strong>${user.pizzaCount}</strong><span>Gesammelte Pizzen</span></div>
      <div class="stats-card"><strong>${vouchers.length}</strong><span>Offene Gutscheine</span></div>
      <div class="stats-card"><strong>${rewardProgress.remaining === 0 ? "Jetzt" : rewardProgress.remaining}</strong><span>${rewardProgress.remaining === 0 ? "Reward bereit" : "Bis nächster Reward"}</span></div>
    </section>

    <section class="grid two">
      <div class="card">
        <div class="section-head"><h3>Rewards</h3><p>Mit Punkten freischalten.</p></div>
        <div class="reward-grid">
          ${rewards.map(reward => `
            <div class="reward-card ${reward.canRedeem ? "reward-open" : ""}">
              <div class="reward-top"><strong>${escapeHtml(reward.title)}</strong><span class="reward-cost">${reward.cost} Pkt</span></div>
              <p class="muted" style="margin:0">${escapeHtml(reward.description)}</p>
              <div class="status-line">${reward.canRedeem ? "Jetzt einlösbar" : "Noch nicht freigeschaltet"}</div>
              <form method="post" action="/account/redeem-reward">
                <input type="hidden" name="rewardId" value="${reward.id}" />
                <button class="btn ${reward.canRedeem ? "btn-primary" : "btn-ghost"}" ${reward.canRedeem ? "" : "disabled"} type="submit">${reward.canRedeem ? "Reward erzeugen" : "Noch nicht verfügbar"}</button>
              </form>
            </div>
          `).join("")}
        </div>
      </div>

      <div class="card">
        <div class="section-head"><h3>Gutscheine & Codes</h3><p>Offene Vorteile für den nächsten Besuch.</p></div>
        ${pizzaVoucher ? `<div class="status-line" style="margin-bottom:12px"><strong>Gratis-Pizza freigeschaltet:</strong> <span class="voucher-code">${escapeHtml(pizzaVoucher.code)}</span></div>` : ""}
        <div class="voucher-list">
          ${vouchers.length ? vouchers.map(v => `
            <div class="voucher-item">
              <div><strong>${escapeHtml(v.title)}</strong><small>${escapeHtml(v.source)}</small></div>
              <div class="voucher-code">${escapeHtml(v.code)}</div>
            </div>
          `).join("") : `<div class="status-line">Keine offenen Gutscheine.</div>`}
        </div>
        <div class="status-line" style="margin-top:12px">Einmalcodes werden im Store vom Team verbucht – nicht direkt im Kundenkonto.</div>
      </div>
    </section>

    <section class="grid two">
      <div class="card">
        <div class="section-head"><h3>Aktionen</h3><p>${actionCards.length ? "Offene Aufgaben." : "Alles erledigt."}</p></div>
        <div class="task-list">${actionCards.length ? actionCards.join("") : `<div class="status-line">Keine offenen Aktionen.</div>`}</div>
      </div>

      <div class="card">
        <div class="section-head"><h3>Verlauf</h3><p>Letzte Buchungen.</p></div>
        <div class="event-list">
          ${events.length ? events.map(event => `
            <div class="event-row">
              <div><strong>${escapeHtml(event.note)}</strong><small>${formatDateTime(event.createdAt)}</small></div>
              <div class="event-side">${escapeHtml(formatEventSide(event))}</div>
            </div>
          `).join("") : `<div class="status-line">Noch keine Aktivitäten vorhanden.</div>`}
        </div>
      </div>
    </section>

    <section class="grid two">
      <div class="card">
        <div class="section-head"><h3>Profil</h3><p>Deine Kontodaten.</p></div>
        <div class="identity-list">
          <div class="identity-row"><div><strong>Name</strong></div><div>${escapeHtml(user.name)}</div></div>
          <div class="identity-row"><div><strong>E-Mail</strong></div><div>${escapeHtml(user.email)}</div></div>
          <div class="identity-row"><div><strong>Status</strong></div><div>${user.verified ? "Bestätigt" : "Nicht bestätigt"}</div></div>
          <div class="button-row"><a class="btn btn-secondary" href="/wallet">Wallet öffnen</a></div>
        </div>
      </div>

      <div class="card">
        <div class="section-head"><h3>Sicherheit</h3><p>Passwort aktualisieren.</p></div>
        <form method="post" action="/account/change-password">
          <label>Aktuelles Passwort<input type="password" name="currentPassword" required autocomplete="current-password" /></label>
          <label>Neues Passwort<input type="password" name="newPassword" required minlength="10" autocomplete="new-password" /></label>
          <label>Neues Passwort wiederholen<input type="password" name="newPasswordConfirm" required minlength="10" autocomplete="new-password" /></label>
          <div class="status-line">${escapeHtml(passwordPolicyHint())}</div>
          <button class="btn btn-primary" type="submit">Passwort speichern</button>
        </form>
      </div>
    </section>

    <script>
      (function () {
        const buttons = document.querySelectorAll(".js-instagram-task");
        const storageKey = "pb-instagram-task";
        async function finalize() {
          const raw = localStorage.getItem(storageKey);
          if (!raw) return;
          let state;
          try { state = JSON.parse(raw); } catch { localStorage.removeItem(storageKey); return; }
          if (!state?.startedAt || Date.now() - Number(state.startedAt) < 5000) return;
          try {
            const res = await fetch("/tasks/instagram/finalize", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "" });
            if (res.redirected) {
              localStorage.removeItem(storageKey);
              window.location.href = res.url;
            }
          } catch (error) { console.error(error); }
        }
        buttons.forEach(btn => btn.addEventListener("click", async () => {
          try {
            const res = await fetch("/tasks/instagram/start", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "" });
            if (res.ok) {
              localStorage.setItem(storageKey, JSON.stringify({ startedAt: Date.now() }));
              setTimeout(finalize, 5200);
            }
          } catch (error) { console.error(error); }
        }));
        setTimeout(finalize, 700);
      })();
    </script>
  `;
  res.send(page({ title: "Kundenkonto", user, body, description: "Punkte, Rewards, Wallet und Aktionen an einem Ort." }));
});

app.post("/account/change-password", authRequired, rateLimit({ windowMs: 15 * 60 * 1000, max: 20, store: authRateStore, name: "change-password" }), async (req, res) => {
  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");
  const newPasswordConfirm = String(req.body.newPasswordConfirm || "");
  const currentUser = await prisma.user.findUnique({ where: { id: req.user.id } });
  if (!currentUser) return res.redirect("/account?error=Konto+nicht+gefunden");
  if (!await bcrypt.compare(currentPassword, currentUser.passwordHash)) return res.redirect("/account?error=Aktuelles+Passwort+falsch");
  if (newPassword !== newPasswordConfirm) return res.redirect("/account?error=Neue+Passwörter+stimmen+nicht+überein");
  const pw = validatePassword(newPassword, currentUser.email, currentUser.name);
  if (!pw.valid) return res.redirect(`/account?error=${encodeURIComponent(pw.message)}`);
  if (await bcrypt.compare(newPassword, currentUser.passwordHash)) return res.redirect("/account?error=Bitte+ein+anderes+Passwort+verwenden");
  const updatedUser = await prisma.user.update({ where: { id: currentUser.id }, data: { passwordHash: await bcrypt.hash(newPassword, 12) } });
  setSession(res, updatedUser);
  res.redirect("/account?success=Passwort+aktualisiert");
});

app.post("/account/redeem-code", authRequired, async (req, res) => {
  res.redirect("/account?error=Einmalcodes+werden+vom+Team+im+Adminbereich+verbucht");
});

app.post("/account/redeem-reward", authRequired, async (req, res) => {
  const reward = rewardDefs.find(r => r.id === String(req.body.rewardId || ""));
  if (!reward) return res.redirect("/account?error=Reward+nicht+gefunden");
  try {
    await prisma.$transaction(async tx => {
      const freshUser = await tx.user.findUnique({ where: { id: req.user.id } });
      if (!freshUser) throw new Error("USER_NOT_FOUND");
      if (freshUser.points < reward.cost) throw new Error("NOT_ENOUGH_POINTS");
      await addEvent(req.user.id, "redeem", -reward.cost, 0, `Reward eingelöst: ${reward.title}`, { rewardId: reward.id }, tx);
      await createVoucher(req.user.id, reward.title, "points-redeem", { rewardId: reward.id }, tx);
    });
    res.redirect("/account?success=Reward+eingelöst");
  } catch (error) {
    if (error.message === "NOT_ENOUGH_POINTS") return res.redirect("/account?error=Nicht+genug+Punkte");
    console.error(error);
    res.redirect("/account?error=Reward+konnte+nicht+eingelöst+werden");
  }
});

app.get("/instagram-task", authRequired, (req, res) => res.redirect("/account"));

app.post("/tasks/instagram/start", authRequired, async (req, res) => {
  const task = await getTaskState(req.user.id, "instagram");
  if (task.claimedAt) return res.json({ ok: false, claimed: true });
  await prisma.taskState.update({ where: { id: task.id }, data: { clickedAt: nowDate(), status: "opened" } });
  res.json({ ok: true });
});
app.post("/tasks/instagram/finalize", authRequired, async (req, res) => {
  const task = await getTaskState(req.user.id, "instagram");
  if (!task.clickedAt) return res.redirect("/account?error=Instagram-Aktion+nicht+gestartet");
  if (task.claimedAt) return res.redirect("/account?error=Instagram+bereits+abgeschlossen");
  const secondsSinceOpen = (Date.now() - new Date(task.clickedAt).getTime()) / 1000;
  if (secondsSinceOpen < 5) return res.redirect("/account?error=Bitte+warte+einen+Moment");
  await prisma.$transaction(async tx => {
    await tx.taskState.update({ where: { id: task.id }, data: { claimedAt: nowDate(), status: "done" } });
    await addEvent(req.user.id, "instagram", 25, 0, "Instagram Aktion abgeschlossen", {}, tx);
  });
  res.redirect("/account?success=Instagram+Aktion+abgeschlossen");
});

app.post("/tasks/review/submit", authRequired, async (req, res) => {
  const link = String(req.body.link || "").trim();
  if (!/^https?:\/\//i.test(link)) return res.redirect("/account?error=Bitte+einen+gültigen+Link+eingeben");
  if (await pendingSubmission(req.user.id, "review")) return res.redirect("/account?error=Für+diese+Aktion+läuft+bereits+eine+Prüfung");
  await prisma.submission.create({ data: { id: uid(), userId: req.user.id, type: "review", taskId: null, link, status: "pending", rewardPoints: 0, note: "Google Bewertung", createdAt: nowDate() } });
  res.redirect("/account?success=Google-Bewertungs-Link+eingereicht");
});

app.post("/tasks/tiktok", authRequired, async (req, res) => {
  const link = String(req.body.link || "").trim();
  if (!/^https?:\/\//i.test(link)) return res.redirect("/account?error=Bitte+einen+gültigen+Link+eingeben");
  if (await pendingSubmission(req.user.id, "tiktok")) return res.redirect("/account?error=Für+diese+Aktion+läuft+bereits+eine+Prüfung");
  await prisma.submission.create({ data: { id: uid(), userId: req.user.id, type: "tiktok", taskId: null, link, status: "pending", rewardPoints: 50, note: "TikTok Beitrag", createdAt: nowDate() } });
  res.redirect("/account?success=TikTok-Link+eingereicht");
});

app.post("/tasks/custom/:taskId/submit", authRequired, async (req, res) => {
  const task = await prisma.customTask.findFirst({ where: { id: String(req.params.taskId || ""), active: true } });
  const link = String(req.body.link || "").trim();
  if (!task) return res.redirect("/account?error=Task+nicht+gefunden");
  if (!/^https?:\/\//i.test(link)) return res.redirect("/account?error=Bitte+einen+gültigen+Link+eingeben");
  if (await pendingSubmission(req.user.id, "custom", task.id)) return res.redirect("/account?error=Für+diese+Aktion+läuft+bereits+eine+Prüfung");
  await prisma.submission.create({ data: { id: uid(), userId: req.user.id, type: "custom", taskId: task.id, link, status: "pending", rewardPoints: Number(task.points || 0), note: task.title, createdAt: nowDate() } });
  res.redirect("/account?success=Task-Link+eingereicht");
});

app.get("/wallet", authRequired, async (req, res) => {
  const qr = await memberQrDataUrl(req.user);
  const activeVoucher = (await getOpenVouchers(req.user.id))[0] || null;
  const body = `
    ${renderFlash(req)}
    <section class="grid two">
      <div class="card">
        <div class="eyebrow">Wallet</div>
        <h2 style="margin:12px 0 8px">Digitale Kundenkarte</h2>
        <p class="muted" style="margin:0">Für Store-Scans und den Wallet-Pass.</p>
        <div class="button-row" style="margin-top:18px">
          <a class="btn btn-primary" href="/wallet/pass">Wallet Pass laden</a>
          <a class="btn btn-secondary" href="/account">Zurück zum Konto</a>
        </div>
        <div class="status-line" style="margin-top:16px">${activeVoucher ? `Offener Gutschein: <strong>${escapeHtml(activeVoucher.title)}</strong> (${escapeHtml(activeVoucher.code)})` : "Aktuell ist kein Gutschein offen"}</div>
      </div>
      <div class="card" style="display:grid;justify-items:center;gap:14px">
        <img class="qr-image" src="${qr}" alt="Wallet QR" />
        <div class="status-line"><code>lpw:${escapeHtml(req.user.walletToken)}</code></div>
      </div>
    </section>
  `;
  res.send(page({ title: "Wallet", user: req.user, body, description: "Deine Pizza-Berlino-Karte für Punkte, Rewards und Gutscheine." }));
});

app.get("/wallet/pass", authRequired, async (req, res) => {
  if (!WALLETWALLET_API_KEY) return res.redirect("/wallet?error=WalletWallet+API-Key+fehlt");
  const activeVoucher = (await getOpenVouchers(req.user.id))[0] || null;
  const displayValue = activeVoucher ? `${req.user.name} • ${activeVoucher.title}` : req.user.name;
  try {
    const response = await fetch("https://api.walletwallet.dev/api/pkpass", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${WALLETWALLET_API_KEY}` },
      body: JSON.stringify({ barcodeValue: `lpw:${req.user.walletToken}`, barcodeFormat: "QR", title: BRAND_NAME, label: "Mitglied", value: displayValue, colorPreset: WALLETWALLET_COLOR_PRESET, expirationDays: 365 })
    });
    if (!response.ok) return res.redirect(`/wallet?error=${encodeURIComponent(`WalletWallet+Fehler:+${await response.text()}`)}`);
    const buffer = Buffer.from(await response.arrayBuffer());
    res.setHeader("Content-Type", "application/vnd.apple.pkpass");
    res.setHeader("Content-Disposition", `attachment; filename="pizza-berlino-${req.user.id}.pkpass"`);
    res.send(buffer);
  } catch {
    res.redirect("/wallet?error=WalletWallet+Anfrage+fehlgeschlagen");
  }
});

app.get("/admin", adminRequired, async (req, res) => {
  const [scannerConfig, userCount, pendingCount, openVoucherCount, users, pendingSubmissions, customTasks, recentCodes, voucherCounts] = await Promise.all([
    ensureScannerConfig(),
    prisma.user.count(),
    prisma.submission.count({ where: { status: "pending" } }),
    prisma.voucher.count({ where: { status: "open" } }),
    prisma.user.findMany({ orderBy: { createdAt: "desc" } }),
    prisma.submission.findMany({ where: { status: "pending" }, include: { user: true }, orderBy: { createdAt: "desc" } }),
    prisma.customTask.findMany({ where: { active: true }, orderBy: { createdAt: "desc" } }),
    prisma.adminCode.findMany({ orderBy: { createdAt: "desc" }, take: 12 }),
    prisma.voucher.groupBy({ by: ["userId"], where: { status: "open" }, _count: { _all: true } })
  ]);
  const voucherCountMap = new Map(voucherCounts.map(entry => [entry.userId, entry._count._all]));

  const body = `
    ${renderFlash(req)}

    <section class="grid two">
      <div class="card" style="background:linear-gradient(135deg,#fff8f2 0%,#fffdf9 100%)">
        <div class="eyebrow">Admin Hub</div>
        <div class="stat-grid" style="margin-top:14px">
          <div class="stats-card"><strong>${userCount}</strong><span>Kunden</span></div>
          <div class="stats-card"><strong>${pendingCount}</strong><span>Prüfungen</span></div>
          <div class="stats-card"><strong>${openVoucherCount}</strong><span>Voucher offen</span></div>
          <div class="stats-card"><strong>PIN</strong><span>Pflicht für Scans</span></div>
        </div>
      </div>
      <div class="card">
        <h3 style="margin:0 0 8px">Staff PIN</h3>
        <p class="muted" style="margin:0 0 16px">Wird für Scan, Voucher und Einmalcodes genutzt.</p>
        <label><input id="adminSharedPin" type="password" placeholder="PIN" autocomplete="one-time-code" inputmode="numeric" /></label>
      </div>
    </section>

    <section class="tabbar">
      <div class="button-row">
        <button class="btn btn-primary adminTabBtn" type="button" data-target="panel-checkin">Check-in</button>
        <button class="btn btn-ghost adminTabBtn" type="button" data-target="panel-custom">Scanner & Codes</button>
        <button class="btn btn-ghost adminTabBtn" type="button" data-target="panel-voucher">Voucher</button>
        <button class="btn btn-ghost adminTabBtn" type="button" data-target="panel-managing">Moderation</button>
      </div>
    </section>

    <section class="admin-panel" id="panel-checkin">
      <section class="grid two">
        <div class="card">
          <div class="section-head"><h3>Check-in</h3><p>Fixe Buchung.</p></div>
          <div class="button-row"><button class="btn btn-primary" id="startCheckinScan">Scanner starten</button><button class="btn btn-secondary" id="stopCheckinScan" disabled>Stoppen</button></div>
          <div id="checkinScanStatus" class="status-line" style="margin-top:14px">Bereit.</div>
          <div class="pill" style="margin-top:12px;text-transform:none;letter-spacing:0">${escapeHtml(scannerConfigSummary(DAILY_CHECKIN_CONFIG))}</div>
        </div>
        <div class="card"><div class="section-head"><h3>Kamera</h3><p>QR-Code scannen.</p></div><div id="readerCheckin" class="reader"></div></div>
      </section>
      <section class="card"><div class="section-head"><h3>Letzte Check-ins</h3><p>Neueste Buchungen.</p></div><div id="checkinLog" class="event-list"></div></section>
    </section>

    <section class="admin-panel" id="panel-custom" hidden>
      <section class="grid two">
        <form class="card" method="post" action="/admin/scanner-config">
          <div class="section-head"><h3>Scanner Setup</h3><p>Werte für die Buchung.</p></div>
          <label>Label<input name="label" required value="${escapeHtml(scannerConfig.label)}" /></label>
          <label>Punkte<input name="addPoints" type="number" value="${Number(scannerConfig.addPoints || 0)}" /></label>
          <label>Pizzen<input name="addPizzas" type="number" value="${Number(scannerConfig.addPizzas || 0)}" /></label>
          <label><input type="checkbox" name="oncePerDay" ${scannerConfig.oncePerDay ? "checked" : ""} /> Nur 1x pro Tag</label>
          <label><input type="checkbox" name="active" ${scannerConfig.active ? "checked" : ""} /> Aktiv</label>
          <button class="btn btn-primary" type="submit">Speichern</button>
        </form>
        <div class="card">
          <div class="section-head"><h3>Scanner</h3><p>Direkt nutzen.</p></div>
          <div class="pill" style="text-transform:none;letter-spacing:0">${escapeHtml(scannerConfigSummary(scannerConfig))}</div>
          <div class="button-row" style="margin-top:14px"><button class="btn btn-primary" type="button" id="startCustomScan">Scanner starten</button><button class="btn btn-secondary" type="button" id="stopCustomScan" disabled>Stoppen</button></div>
          <div id="customScanStatus" class="status-line" style="margin-top:14px">Bereit.</div>
          <div id="readerCustom" class="reader" style="margin-top:14px"></div>
        </div>
      </section>

      <section class="grid two">
        <form class="card" method="post" action="/admin/create-code">
          <div class="section-head"><h3>Einmalcode erstellen</h3><p>Für spätere Verbuchung durch das Team.</p></div>
          <label>Label<input name="label" required placeholder="2 bestellte Pizzen / +25 Punkte" /></label>
          <label>Punkte<input name="addPoints" type="number" value="0" /></label>
          <label>Pizzen<input name="addPizzas" type="number" value="0" /></label>
          <button class="btn btn-secondary" type="submit">Code erzeugen</button>
        </form>

        <div class="card">
          <div class="section-head"><h3>Einmalcode beim Kunden verbuchen</h3><p>QR scannen und Code eingeben.</p></div>
          <div class="button-row"><button class="btn btn-primary" type="button" id="startCodeApplyScan">Kunden scannen</button><button class="btn btn-secondary" type="button" id="stopCodeApplyScan" disabled>Stoppen</button></div>
          <div id="adminCodeApplyStatus" class="status-line" style="margin-top:14px">Bereit.</div>
          <div id="readerCodeApply" class="reader" style="margin-top:14px"></div>
          <label style="margin-top:14px">Einmalcode<input id="adminCodeApplyInput" placeholder="z. B. 8AF4C21D" autocomplete="off" /></label>
          <button class="btn btn-secondary" type="button" id="applyAdminCodeBtn" disabled>Code verbuchen</button>
        </div>
      </section>

      <section class="card"><div class="section-head"><h3>Letzte Scans & Codebuchungen</h3><p>Neueste Scanner-Buchungen.</p></div><div id="customScanLog" class="event-list"></div></section>
    </section>

    <section class="admin-panel" id="panel-voucher" hidden>
      <section class="grid two">
        <div class="card">
          <div class="section-head"><h3>Voucher Scan</h3><p>Kunde scannen und Voucher auswählen.</p></div>
          <div class="button-row"><button class="btn btn-primary" id="startVoucherScan">Scanner starten</button><button class="btn btn-secondary" id="stopVoucherScan" disabled>Stoppen</button></div>
          <div id="voucherScanStatus" class="status-line" style="margin-top:14px">Bereit.</div>
        </div>
        <div class="card"><div class="section-head"><h3>Kamera</h3><p>QR-Code scannen.</p></div><div id="readerVoucher" class="reader"></div></div>
      </section>
      <section class="card"><div class="section-head"><h3>Offene Voucher</h3><p>Nach dem Scan sichtbar.</p></div><div id="voucherSelection"><p class="muted">Noch kein Kunde gescannt.</p></div></section>
      <section class="card"><div class="section-head"><h3>Einlösungen</h3><p>Zuletzt verbuchte Voucher.</p></div><div id="voucherLog" class="event-list"></div></section>
    </section>

    <section class="admin-panel" id="panel-managing" hidden>
      <section class="grid two">
        <form class="card" method="post" action="/admin/custom-tasks">
          <div class="section-head"><h3>Neue Aktion</h3><p>Kompakt anlegen.</p></div>
          <label>Titel<input name="title" required placeholder="Like + Kommentar" /></label>
          <label>Beschreibung<input name="description" required placeholder="Kurze Erklärung" /></label>
          <label>Ziel-Link<input name="targetUrl" placeholder="https://instagram.com/..." /></label>
          <label>Punkte<input name="points" type="number" value="20" required /></label>
          <label><input type="checkbox" name="active" checked /> Aktiv</label>
          <button class="btn btn-primary" type="submit">Aktion erstellen</button>
        </form>
        <div class="card">
          <div class="section-head"><h3>Aktionen</h3><p>Bestehende Aktionen.</p></div>
          <div class="event-list">
            ${customTasks.length ? customTasks.map(task => `
              <div class="event-row">
                <div><strong>${escapeHtml(task.title)}</strong><small>${escapeHtml(task.description)}</small>${task.targetUrl ? `<div><a href="${escapeHtml(task.targetUrl)}" target="_blank" rel="noreferrer" style="text-decoration:none;color:var(--accent-dark);font-weight:800">${escapeHtml(task.targetUrl)}</a></div>` : ""}</div>
                <div class="button-row"><span class="pill" style="text-transform:none;letter-spacing:0">${task.points} Pkt</span><form method="post" action="/admin/custom-tasks/${task.id}/toggle"><button class="btn btn-ghost" type="submit">${task.active ? "Deaktivieren" : "Aktivieren"}</button></form></div>
              </div>
            `).join("") : `<div class="status-line">Noch keine Aktionen erstellt.</div>`}
          </div>
        </div>
      </section>

      <section class="card">
        <div class="section-head"><h3>Offene Prüfungen</h3><p>Einreichen, prüfen, freigeben.</p></div>
        <div class="event-list">
          ${pendingSubmissions.length ? pendingSubmissions.map(s => `
            <div class="event-row">
              <div><strong>${escapeHtml(s.user?.name || "Unbekannt")} · ${escapeHtml(submissionLabel(s))}</strong><small><a href="${escapeHtml(s.link)}" target="_blank" rel="noreferrer" style="text-decoration:none;color:var(--accent-dark);font-weight:800">${escapeHtml(s.link)}</a></small></div>
              <div class="button-row">
                <form method="post" action="/admin/submission/${s.id}/approve"><button class="btn btn-primary">Freigeben</button></form>
                <form method="post" action="/admin/submission/${s.id}/reject"><button class="btn btn-ghost">Ablehnen</button></form>
              </div>
            </div>
          `).join("") : `<div class="status-line">Keine offenen Prüfungen.</div>`}
        </div>
      </section>

      <section class="grid two">
        <div class="card">
          <div class="section-head"><h3>Einmalcodes</h3><p>Letzte Codes.</p></div>
          <div class="event-list">
            ${recentCodes.length ? recentCodes.map(code => `
              <div class="event-row">
                <div><strong>${escapeHtml(code.code)}</strong><small>${escapeHtml(code.label)}</small></div>
                <div class="event-side">${code.usedAt ? "verbucht" : "offen"}</div>
              </div>
            `).join("") : `<div class="status-line">Noch keine Codes.</div>`}
          </div>
        </div>

        <div class="card">
          <div class="section-head"><h3>Kunden</h3><p>Konten im Überblick.</p></div>
          <div class="table-wrap">
            <table><thead><tr><th>Name</th><th>Punkte</th><th>Pizzen</th><th>Voucher</th></tr></thead><tbody>
              ${users.map(u => `<tr><td>${escapeHtml(u.name)}<small>${escapeHtml(u.email)}</small></td><td>${u.points}</td><td>${u.pizzaCount}</td><td>${voucherCountMap.get(u.id) || 0}</td></tr>`).join("")}
            </tbody></table>
          </div>
        </div>
      </section>
    </section>

    <script src="https://unpkg.com/html5-qrcode"></script>
    <script>
      const pinInput=document.getElementById("adminSharedPin");
      const panelButtons=Array.from(document.querySelectorAll(".adminTabBtn"));
      const panels=Array.from(document.querySelectorAll(".admin-panel"));
      const scannerState={};
      let selectedVouchers=[], selectedVoucherUser="", selectedCodePayload="";

      function getPin(){ return pinInput?.value.trim() || ""; }
      function esc(v){ return String(v).replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch])); }
      function activatePanel(id){
        panels.forEach(panel=>{ panel.hidden=panel.id!==id; });
        panelButtons.forEach(btn=>{ const active=btn.dataset.target===id; btn.classList.toggle("btn-primary",active); btn.classList.toggle("btn-ghost",!active); });
        window.location.hash=id;
      }
      panelButtons.forEach(btn=>btn.addEventListener("click",()=>activatePanel(btn.dataset.target)));
      activatePanel(document.getElementById((window.location.hash||"#panel-checkin").replace(/^#/,"")) ? (window.location.hash||"#panel-checkin").replace(/^#/,"") : "panel-checkin");

      function addLog(logId, html){
        const el=document.getElementById(logId);
        if(!el) return;
        el.insertAdjacentHTML("afterbegin","<div class='event-row'>"+html+"</div>");
      }
      async function stopScanner(name,startId,stopId){
        const current=scannerState[name];
        if(current?.instance && current.running){ try{ await current.instance.stop(); }catch{} try{ await current.instance.clear(); }catch{} }
        scannerState[name]={ instance:null, running:false };
        const startBtn=document.getElementById(startId); const stopBtn=document.getElementById(stopId);
        if(startBtn) startBtn.disabled=false; if(stopBtn) stopBtn.disabled=true;
      }
      async function startBasicScanner({ name, readerId, startId, stopId, statusId, endpoint, logId, successSide, onSuccess }){
        const statusEl=document.getElementById(statusId);
        try{
          if(!window.isSecureContext){ statusEl.textContent="HTTPS oder localhost nötig."; return; }
          const pin=getPin(); if(!pin){ statusEl.textContent="Bitte zuerst die Staff PIN eingeben."; return; }
          const scanner=new Html5Qrcode(readerId); scannerState[name]={ instance:scanner, running:true };
          await scanner.start({ facingMode:"environment" }, { fps:10, qrbox:{ width:220, height:220 } }, async decodedText=>{
            if(!scannerState[name]?.running) return;
            scannerState[name].running=false;
            try{
              const form=new URLSearchParams(); form.set("payload",decodedText); form.set("pin",pin);
              const res=await fetch(endpoint,{ method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body:form.toString() });
              const data=await res.json();
              if(!res.ok || !data.ok){
                statusEl.textContent=data.error || "Fehler";
                if(logId) addLog(logId,"<div><strong>Fehler</strong><small>"+esc(data.error || "Unbekannt")+"</small></div><div class='event-side'>–</div>");
                await stopScanner(name,startId,stopId); return;
              }
              statusEl.textContent=data.message;
              if(logId) addLog(logId,"<div><strong>"+esc(data.userName || "Kunde")+"</strong><small>"+esc(data.message || "Erfolgreich")+"</small></div><div class='event-side'>"+successSide(data)+"</div>");
              if(typeof onSuccess === "function") onSuccess(decodedText, data);
              await stopScanner(name,startId,stopId);
            }catch{
              statusEl.textContent="Scannerfehler";
              await stopScanner(name,startId,stopId);
            }
          });
          document.getElementById(startId).disabled=true;
          document.getElementById(stopId).disabled=false;
          statusEl.textContent="Scanner läuft...";
        }catch{
          statusEl.textContent="Scanner konnte nicht starten.";
          await stopScanner(name,startId,stopId);
        }
      }

      document.getElementById("startCheckinScan")?.addEventListener("click",()=>startBasicScanner({ name:"checkin", readerId:"readerCheckin", startId:"startCheckinScan", stopId:"stopCheckinScan", statusId:"checkinScanStatus", endpoint:"/admin/checkin-scan", logId:"checkinLog", successSide:data=>"+"+(data.addPoints||0) }));
      document.getElementById("stopCheckinScan")?.addEventListener("click",async()=>{ await stopScanner("checkin","startCheckinScan","stopCheckinScan"); document.getElementById("checkinScanStatus").textContent="Scanner gestoppt."; });

      document.getElementById("startCustomScan")?.addEventListener("click",()=>startBasicScanner({ name:"custom", readerId:"readerCustom", startId:"startCustomScan", stopId:"stopCustomScan", statusId:"customScanStatus", endpoint:"/admin/custom-scan", logId:"customScanLog", successSide:data=>"+"+(data.addPoints||0)+" / +"+(data.addPizzas||0) }));
      document.getElementById("stopCustomScan")?.addEventListener("click",async()=>{ await stopScanner("custom","startCustomScan","stopCustomScan"); document.getElementById("customScanStatus").textContent="Scanner gestoppt."; });

      document.getElementById("startCodeApplyScan")?.addEventListener("click",()=>startBasicScanner({
        name:"codeApply", readerId:"readerCodeApply", startId:"startCodeApplyScan", stopId:"stopCodeApplyScan", statusId:"adminCodeApplyStatus", endpoint:"/admin/redeem-scan",
        successSide:()=>"", onSuccess:(decodedText,data)=>{ selectedCodePayload=decodedText; document.getElementById("applyAdminCodeBtn").disabled=false; document.getElementById("adminCodeApplyStatus").textContent="Kunde erkannt: "+(data.userName || "Unbekannt"); }
      }));
      document.getElementById("stopCodeApplyScan")?.addEventListener("click",async()=>{ await stopScanner("codeApply","startCodeApplyScan","stopCodeApplyScan"); document.getElementById("adminCodeApplyStatus").textContent="Scanner gestoppt."; });
      document.getElementById("applyAdminCodeBtn")?.addEventListener("click",async()=>{
        const pin=getPin(), code=document.getElementById("adminCodeApplyInput")?.value.trim().toUpperCase() || "", statusEl=document.getElementById("adminCodeApplyStatus");
        if(!pin){ statusEl.textContent="Bitte zuerst die Staff PIN eingeben."; return; }
        if(!selectedCodePayload){ statusEl.textContent="Bitte zuerst einen Kunden scannen."; return; }
        if(!code){ statusEl.textContent="Bitte einen Einmalcode eingeben."; return; }
        const form=new URLSearchParams(); form.set("pin",pin); form.set("payload",selectedCodePayload); form.set("code",code);
        const res=await fetch("/admin/apply-admin-code",{ method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body:form.toString() });
        const data=await res.json();
        if(!res.ok || !data.ok){ statusEl.textContent=data.error || "Fehler"; addLog("customScanLog","<div><strong>Fehler</strong><small>"+esc(data.error || "Unbekannt")+"</small></div><div class='event-side'>–</div>"); return; }
        statusEl.textContent=data.message;
        addLog("customScanLog","<div><strong>"+esc(data.userName)+"</strong><small>"+esc(data.label || data.message)+" · "+esc(data.code)+"</small></div><div class='event-side'>+"+esc(String(data.addPoints || 0))+" / +"+esc(String(data.addPizzas || 0))+"</div>");
        selectedCodePayload=""; document.getElementById("adminCodeApplyInput").value=""; document.getElementById("applyAdminCodeBtn").disabled=true;
      });

      function renderVoucherSelection(userName, vouchers){
        const el=document.getElementById("voucherSelection");
        if(!vouchers.length){ el.innerHTML="<p class='muted'>Für <strong>"+esc(userName)+"</strong> ist kein offener Voucher vorhanden.</p>"; return; }
        el.innerHTML="<div class='grid two'>"+vouchers.map(v=>"<div class='voucher-item'><div><strong>"+esc(v.title)+"</strong><small>"+esc(v.source || "")+"</small><div class='voucher-code'>"+esc(v.code)+"</div></div><button class='btn btn-primary redeemVoucherBtn' data-voucher-id='"+esc(v.id)+"'>Einlösen</button></div>").join("")+"</div>";
        document.querySelectorAll(".redeemVoucherBtn").forEach(btn=>btn.addEventListener("click", async()=>{
          const pin=getPin(); const statusEl=document.getElementById("voucherScanStatus");
          if(!pin){ statusEl.textContent="Bitte zuerst die Staff PIN eingeben."; return; }
          const form=new URLSearchParams(); form.set("voucherId", btn.getAttribute("data-voucher-id")); form.set("pin", pin);
          const res=await fetch("/admin/redeem-voucher",{ method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body:form.toString() });
          const data=await res.json();
          if(!res.ok || !data.ok){ statusEl.textContent=data.error || "Fehler"; addLog("voucherLog","<div><strong>Fehler</strong><small>"+esc(data.error || "Unbekannt")+"</small></div><div class='event-side'>–</div>"); return; }
          statusEl.textContent=data.message;
          addLog("voucherLog","<div><strong>"+esc(data.userName)+"</strong><small>"+esc(data.message)+"</small></div><div class='event-side'>"+esc(data.voucherTitle)+"</div>");
          selectedVouchers=selectedVouchers.filter(v=>v.id!==btn.getAttribute("data-voucher-id")); renderVoucherSelection(selectedVoucherUser, selectedVouchers);
        }));
      }

      document.getElementById("startVoucherScan")?.addEventListener("click", async()=>{
        const statusEl=document.getElementById("voucherScanStatus");
        try{
          if(!window.isSecureContext){ statusEl.textContent="HTTPS oder localhost nötig."; return; }
          const pin=getPin(); if(!pin){ statusEl.textContent="Bitte zuerst die Staff PIN eingeben."; return; }
          const scanner=new Html5Qrcode("readerVoucher"); scannerState.voucher={ instance:scanner, running:true };
          await scanner.start({ facingMode:"environment" }, { fps:10, qrbox:{ width:220, height:220 } }, async decodedText=>{
            if(!scannerState.voucher?.running) return;
            scannerState.voucher.running=false;
            try{
              const form=new URLSearchParams(); form.set("payload",decodedText); form.set("pin",pin);
              const res=await fetch("/admin/redeem-scan",{ method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body:form.toString() });
              const data=await res.json();
              if(!res.ok || !data.ok){ statusEl.textContent=data.error || "Fehler"; document.getElementById("voucherSelection").innerHTML="<p class='muted'>"+esc(data.error || "Fehler")+"</p>"; await stopScanner("voucher","startVoucherScan","stopVoucherScan"); return; }
              selectedVoucherUser=data.userName || ""; selectedVouchers=data.vouchers || []; statusEl.textContent=data.message; renderVoucherSelection(selectedVoucherUser, selectedVouchers); await stopScanner("voucher","startVoucherScan","stopVoucherScan");
            }catch{
              statusEl.textContent="Scannerfehler"; await stopScanner("voucher","startVoucherScan","stopVoucherScan");
            }
          });
          document.getElementById("startVoucherScan").disabled=true; document.getElementById("stopVoucherScan").disabled=false; statusEl.textContent="Scanner läuft...";
        }catch{
          statusEl.textContent="Scanner konnte nicht starten."; await stopScanner("voucher","startVoucherScan","stopVoucherScan");
        }
      });
      document.getElementById("stopVoucherScan")?.addEventListener("click", async()=>{ await stopScanner("voucher","startVoucherScan","stopVoucherScan"); document.getElementById("voucherScanStatus").textContent="Scanner gestoppt."; });
    </script>
  `;
  res.send(page({ title: "Admin", user: req.user, body, description: "Scans, Voucher, Codes und Moderation." }));
});

app.get("/staff", adminRequired, (req, res) => res.redirect("/admin#panel-checkin"));
app.get("/staff/redeem", adminRequired, (req, res) => res.redirect("/admin#panel-voucher"));

app.post("/admin/checkin-scan", adminRequired, async (req, res) => {
  const pin = String(req.body.pin || "").trim();
  const payload = String(req.body.payload || "").trim();
  if (!assertStaffPin(pin)) return res.status(400).json({ ok: false, error: "PIN falsch" });
  if (!payload.startsWith("lpw:")) return res.status(400).json({ ok: false, error: "Ungültiger QR" });
  const user = await findUserByWalletPayload(payload);
  if (!user) return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });
  if (DAILY_CHECKIN_CONFIG.oncePerDay) {
    const already = await prisma.event.findFirst({ where: { userId: user.id, type: "daily-checkin", dayKey: dayKey() } });
    if (already) return res.status(400).json({ ok: false, error: "Heute bereits eingecheckt" });
  }
  await addEvent(user.id, "daily-checkin", DAILY_CHECKIN_CONFIG.addPoints, DAILY_CHECKIN_CONFIG.addPizzas, DAILY_CHECKIN_CONFIG.label, { scannedBy: req.user.email, mode: "checkin" });
  res.json({ ok: true, message: `${DAILY_CHECKIN_CONFIG.label} verbucht`, userName: user.name, addPoints: DAILY_CHECKIN_CONFIG.addPoints, addPizzas: DAILY_CHECKIN_CONFIG.addPizzas });
});

app.post("/admin/custom-scan", adminRequired, async (req, res) => {
  const pin = String(req.body.pin || "").trim();
  const payload = String(req.body.payload || "").trim();
  const cfg = await ensureScannerConfig();
  if (!assertStaffPin(pin)) return res.status(400).json({ ok: false, error: "PIN falsch" });
  if (!cfg.active) return res.status(400).json({ ok: false, error: "Scanner deaktiviert" });
  if (!payload.startsWith("lpw:")) return res.status(400).json({ ok: false, error: "Ungültiger QR" });
  const user = await findUserByWalletPayload(payload);
  if (!user) return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });
  const configHash = JSON.stringify({ label: cfg.label, addPoints: cfg.addPoints, addPizzas: cfg.addPizzas, oncePerDay: cfg.oncePerDay, active: cfg.active });
  if (cfg.oncePerDay && await hasCustomScanAlreadyRun(user.id, configHash)) {
    return res.status(400).json({ ok: false, error: "Heute bereits mit dieser Aktion gescannt" });
  }
  await addEvent(user.id, "staff-scan", Number(cfg.addPoints || 0), Number(cfg.addPizzas || 0), cfg.label || "Scanner Aktion", { scannedBy: req.user.email, configHash, mode: "custom" });
  res.json({ ok: true, message: `${cfg.label} verbucht`, userName: user.name, addPoints: Number(cfg.addPoints || 0), addPizzas: Number(cfg.addPizzas || 0) });
});

app.post("/admin/redeem-scan", adminRequired, async (req, res) => {
  const pin = String(req.body.pin || "").trim();
  const payload = String(req.body.payload || "").trim();
  if (!assertStaffPin(pin)) return res.status(400).json({ ok: false, error: "PIN falsch" });
  if (!payload.startsWith("lpw:")) return res.status(400).json({ ok: false, error: "Ungültiger QR" });
  const user = await findUserByWalletPayload(payload);
  if (!user) return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });
  const vouchers = await prisma.voucher.findMany({ where: { userId: user.id, status: "open" }, orderBy: { createdAt: "desc" } });
  res.json({ ok: true, message: vouchers.length ? `${vouchers.length} offene Voucher gefunden` : "Kein offener Voucher vorhanden", userName: user.name, vouchers: vouchers.map(v => ({ id: v.id, title: v.title, code: v.code, source: v.source || "" })) });
});

app.post("/admin/redeem-voucher", adminRequired, async (req, res) => {
  const pin = String(req.body.pin || "").trim();
  const voucherId = String(req.body.voucherId || "").trim();
  if (!assertStaffPin(pin)) return res.status(400).json({ ok: false, error: "PIN falsch" });
  const voucher = await prisma.voucher.findUnique({ where: { id: voucherId } });
  if (!voucher) return res.status(404).json({ ok: false, error: "Voucher nicht gefunden" });
  if (voucher.status !== "open") return res.status(400).json({ ok: false, error: "Voucher bereits eingelöst" });
  const user = await prisma.user.findUnique({ where: { id: voucher.userId } });
  if (!user) return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });
  await prisma.$transaction(async tx => {
    await tx.voucher.update({ where: { id: voucher.id }, data: { status: "used", usedAt: nowDate(), usedBy: req.user.email } });
    await tx.event.create({ data: { id: uid(), userId: user.id, type: "voucher-used", points: 0, pizzas: 0, note: `Voucher eingelöst: ${voucher.title}`, meta: { code: voucher.code, scannedBy: req.user.email }, createdAt: nowDate(), dayKey: dayKey() } });
  });
  res.json({ ok: true, message: "Voucher eingelöst", userName: user.name, voucherTitle: voucher.title });
});

app.post("/admin/apply-admin-code", adminRequired, async (req, res) => {
  const pin = String(req.body.pin || "").trim();
  const payload = String(req.body.payload || "").trim();
  const code = String(req.body.code || "").trim().toUpperCase();
  if (!assertStaffPin(pin)) return res.status(400).json({ ok: false, error: "PIN falsch" });
  if (!payload.startsWith("lpw:")) return res.status(400).json({ ok: false, error: "Ungültiger QR" });
  if (!code) return res.status(400).json({ ok: false, error: "Code fehlt" });
  const user = await findUserByWalletPayload(payload);
  if (!user) return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });
  const adminCode = await prisma.adminCode.findUnique({ where: { code } });
  if (!adminCode || adminCode.usedAt) return res.status(404).json({ ok: false, error: "Code ungültig oder bereits verbucht" });
  await prisma.$transaction(async tx => {
    await tx.adminCode.update({ where: { id: adminCode.id }, data: { usedAt: nowDate(), usedByUserId: user.id } });
    await addEvent(user.id, "admin-code", Number(adminCode.addPoints || 0), Number(adminCode.addPizzas || 0), adminCode.label || "Einmalcode", { code: adminCode.code, appliedBy: req.user.email }, tx);
  });
  res.json({ ok: true, message: "Einmalcode verbucht", userName: user.name, label: adminCode.label, addPoints: Number(adminCode.addPoints || 0), addPizzas: Number(adminCode.addPizzas || 0), code: adminCode.code });
});

app.post("/admin/scanner-config", adminRequired, async (req, res) => {
  await prisma.scannerConfig.upsert({
    where: { id: 1 },
    update: { active: !!req.body.active, label: String(req.body.label || "Scanner Aktion").trim(), addPoints: Number(req.body.addPoints || 0), addPizzas: Number(req.body.addPizzas || 0), oncePerDay: !!req.body.oncePerDay },
    create: { id: 1, active: !!req.body.active, label: String(req.body.label || "Scanner Aktion").trim(), addPoints: Number(req.body.addPoints || 0), addPizzas: Number(req.body.addPizzas || 0), oncePerDay: !!req.body.oncePerDay }
  });
  res.redirect("/admin?success=Scanner+gespeichert#panel-custom");
});

app.post("/admin/create-code", adminRequired, async (req, res) => {
  const code = crypto.randomBytes(4).toString("hex").toUpperCase();
  await prisma.adminCode.create({ data: { id: uid(), code, label: String(req.body.label || "Admin Code").trim(), addPoints: Number(req.body.addPoints || 0), addPizzas: Number(req.body.addPizzas || 0), createdAt: nowDate(), createdBy: req.user.email, usedAt: null, usedByUserId: null } });
  res.redirect(`/admin?success=${encodeURIComponent(`Code+erstellt:+${code}`)}#panel-custom`);
});

app.post("/admin/custom-tasks", adminRequired, async (req, res) => {
  const title = String(req.body.title || "").trim();
  const description = String(req.body.description || "").trim();
  const targetUrl = String(req.body.targetUrl || "").trim();
  const points = Number(req.body.points || 0);
  if (!title || !description) return res.redirect("/admin?error=Bitte+Titel+und+Beschreibung+angeben#panel-managing");
  await prisma.customTask.create({ data: { id: uid(), title, description, targetUrl: targetUrl || null, points, active: !!req.body.active, createdAt: nowDate(), createdBy: req.user.email } });
  res.redirect("/admin?success=Aktion+erstellt#panel-managing");
});

app.post("/admin/custom-tasks/:id/toggle", adminRequired, async (req, res) => {
  const task = await prisma.customTask.findUnique({ where: { id: req.params.id } });
  if (!task) return res.redirect("/admin?error=Task+nicht+gefunden#panel-managing");
  await prisma.customTask.update({ where: { id: task.id }, data: { active: !task.active } });
  res.redirect("/admin?success=Aktion+aktualisiert#panel-managing");
});

app.post("/admin/submission/:id/approve", adminRequired, async (req, res) => {
  try {
    await prisma.$transaction(async tx => {
      const submission = await tx.submission.findUnique({ where: { id: String(req.params.id || "") } });
      if (!submission) throw new Error("SUBMISSION_NOT_FOUND");
      if (submission.status !== "pending") throw new Error("SUBMISSION_ALREADY_DONE");
      const user = await tx.user.findUnique({ where: { id: submission.userId } });
      if (!user) throw new Error("USER_NOT_FOUND");
      await tx.submission.update({ where: { id: submission.id }, data: { status: "approved", reviewedAt: nowDate(), reviewedBy: req.user.email } });
      await addEvent(user.id, submission.type, Number(submission.rewardPoints || 0), 0, `${submissionLabel(submission)} freigegeben`, { submissionId: submission.id }, tx);
    });
    res.redirect("/admin?success=Submission+freigegeben#panel-managing");
  } catch (error) {
    if (error.message === "SUBMISSION_NOT_FOUND") return res.redirect("/admin?error=Submission+nicht+gefunden#panel-managing");
    if (error.message === "SUBMISSION_ALREADY_DONE") return res.redirect("/admin?error=Submission+bereits+bearbeitet#panel-managing");
    if (error.message === "USER_NOT_FOUND") return res.redirect("/admin?error=Kunde+nicht+gefunden#panel-managing");
    console.error(error);
    res.redirect("/admin?error=Freigabe+fehlgeschlagen#panel-managing");
  }
});

app.post("/admin/submission/:id/reject", adminRequired, async (req, res) => {
  const submission = await prisma.submission.findUnique({ where: { id: req.params.id } });
  if (!submission) return res.redirect("/admin?error=Submission+nicht+gefunden#panel-managing");
  await prisma.submission.update({ where: { id: submission.id }, data: { status: "rejected", reviewedAt: nowDate(), reviewedBy: req.user.email } });
  res.redirect("/admin?success=Submission+abgelehnt#panel-managing");
});

app.get("/health", async (req, res) => {
  const users = await prisma.user.count();
  res.json({ ok: true, app: BRAND_NAME, users, now: nowIso() });
});

app.listen(PORT, "0.0.0.0", async () => {
  try { await ensureScannerConfig(); } catch (error) { console.error("Scanner config bootstrap failed", error); }
  if (!DEV_AUTO_VERIFY) await verifyMailerConnection();
  console.log(`${BRAND_NAME} läuft auf ${APP_URL}`);
});
