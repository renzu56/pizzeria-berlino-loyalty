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

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(express.urlencoded({ extended: true, limit: "64kb" }));
app.use(express.json({ limit: "64kb" }));
app.use(cookieParser());
app.use("/static", express.static(path.join(__dirname, "public"), { maxAge: "7d", immutable: false }));

const DEV_AUTO_VERIFY = process.env.DEV_AUTO_VERIFY === "true";
const PORT = Number(process.env.PORT || 3000);
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

function normalizeAppUrl(rawValue, port) {
  const fallback = `http://localhost:${port}`;
  const value = String(rawValue || "").trim().replace(/\/$/, "");
  if (!value) return fallback;
  if (/^https?:\/\//i.test(value)) return value;

  const isLocal = /^(localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?$/i.test(value);
  return `${isLocal ? "http" : "https"}://${value}`;
}

const APP_URL = normalizeAppUrl(process.env.APP_URL, PORT);
const BRAND_NAME = process.env.BRAND_NAME || "Pizza Berlino";
const BRAND_SUBTITLE = process.env.BRAND_SUBTITLE || "Loyalitätsprogramm";
const BRAND_LOGO_FILENAME = process.env.BRAND_LOGO_FILENAME || "1773058332279.jfif";
const brandLogoPath = path.join(__dirname, BRAND_LOGO_FILENAME);
const SESSION_SECRET = process.env.SESSION_SECRET || "change_me_super_secret";
const PASSWORD_RESET_EXPIRES_MINUTES = Number(process.env.PASSWORD_RESET_EXPIRES_MINUTES || 30);

const INSTAGRAM_URL = process.env.INSTAGRAM_URL || "https://www.instagram.com/pizza_berlino/";
const REVIEW_URL = process.env.REVIEW_URL || "https://g.page/r/CcF9V1iR1Es9EBM/review";

const WALLETWALLET_API_KEY = process.env.WALLETWALLET_API_KEY || "";
const WALLETWALLET_COLOR_PRESET = process.env.WALLETWALLET_COLOR_PRESET || "red";

const ADMIN_EMAILS = new Set(
  (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map(v => v.trim().toLowerCase())
    .filter(Boolean)
);

const SESSION_COOKIE_NAME = "session";
const SESSION_MAX_AGE_DAYS = Number(process.env.SESSION_MAX_AGE_DAYS || 14);
const AUTH_RATE_LIMIT_WINDOW_MS = Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const AUTH_RATE_LIMIT_MAX = Number(process.env.AUTH_RATE_LIMIT_MAX || 25);
const ADMIN_RATE_LIMIT_WINDOW_MS = Number(process.env.ADMIN_RATE_LIMIT_WINDOW_MS || 60 * 1000);
const ADMIN_RATE_LIMIT_MAX = Number(process.env.ADMIN_RATE_LIMIT_MAX || 180);
const INSTAGRAM_TASK_SECONDS = Number(process.env.INSTAGRAM_TASK_SECONDS || 5);
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);

const requestBuckets = new Map();

const DAILY_CHECKIN_CONFIG = {
  label: "Daily Check-in",
  addPoints: 10,
  addPizzas: 0,
  oncePerDay: true
};

const rewardDefs = [
  { id: "r15", title: "10% Rabatt", cost: 15, description: "10% Rabatt auf die nächste Bestellung." },
  { id: "r100", title: "Kostenloses Getränk", cost: 100, description: "Ein Getränk gratis." },
  { id: "r175", title: "50% Rabatt", cost: 175, description: "50% Rabatt auf die nächste Bestellung." },
  { id: "r300", title: "Kostenlose Pizza", cost: 300, description: "Eine Pizza gratis." }
];

app.get("/brand-logo", (req, res) => {
  if (!fs.existsSync(brandLogoPath)) {
    return res.status(404).send("Logo not found");
  }
  return res.sendFile(brandLogoPath);
});

function uid() {
  return crypto.randomUUID();
}

function nowDate() {
  return new Date();
}

function nowIso() {
  return nowDate().toISOString();
}

function absoluteUrl(pathname) {
  return new URL(pathname, `${APP_URL}/`).toString();
}

function dayKey(date = new Date()) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Berlin",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(date);
}

function formatDateTime(value) {
  if (!value) return "";
  return new Date(value).toLocaleString("de-DE", {
    dateStyle: "short",
    timeStyle: "short"
  });
}

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[ch]));
}

function normalizeCodeInput(value = "") {
  return String(value || "").trim().toUpperCase().replace(/\s+/g, "");
}

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || req.ip || req.socket?.remoteAddress || "unknown";
}

function passwordValidationMessage(password) {
  const value = String(password || "");
  if (value.length < 10) return "Passwort muss mindestens 10 Zeichen lang sein";
  if (!/[a-zäöü]/.test(value)) return "Passwort muss mindestens einen Kleinbuchstaben enthalten";
  if (!/[A-ZÄÖÜ]/.test(value)) return "Passwort muss mindestens einen Großbuchstaben enthalten";
  if (!/\d/.test(value)) return "Passwort muss mindestens eine Zahl enthalten";
  return "";
}

function isAllowedOrigin(req) {
  const origin = String(req.get("origin") || "").trim();
  if (!origin) return true;

  try {
    const requestOrigin = new URL(origin);
    const appOrigin = new URL(APP_URL);
    return requestOrigin.origin === appOrigin.origin || requestOrigin.host === String(req.get("host") || "").trim();
  } catch {
    return false;
  }
}

function createRateLimiter({ windowMs, max, keyPrefix, message }) {
  const safeWindowMs = Math.max(1000, Number(windowMs || 60_000));
  const safeMax = Math.max(1, Number(max || 10));

  return (req, res, next) => {
    const now = Date.now();
    const bucketKey = `${keyPrefix}:${getClientIp(req)}`;
    const bucket = requestBuckets.get(bucketKey) || { count: 0, resetAt: now + safeWindowMs };

    if (bucket.resetAt <= now) {
      bucket.count = 0;
      bucket.resetAt = now + safeWindowMs;
    }

    bucket.count += 1;
    requestBuckets.set(bucketKey, bucket);

    if (requestBuckets.size > 3000) {
      for (const [key, value] of requestBuckets.entries()) {
        if (value.resetAt <= now) requestBuckets.delete(key);
      }
    }

    if (bucket.count > safeMax) {
      const remainingSeconds = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      res.setHeader("Retry-After", String(remainingSeconds));
      if (req.path.startsWith("/admin/") || req.accepts(["json", "html"]) === "json") {
        return res.status(429).json({ ok: false, error: message || "Zu viele Anfragen" });
      }
      return res.status(429).redirect(`/login?error=${encodeURIComponent(message || "Zu viele Anfragen")}`);
    }

    next();
  };
}

app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(self), microphone=(), geolocation=()");
  if (APP_URL.startsWith("https://") || process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

app.use((req, res, next) => {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && !isAllowedOrigin(req)) {
    if (req.path.startsWith("/admin/") || req.accepts(["json", "html"]) === "json") {
      return res.status(403).json({ ok: false, error: "Ungültige Anfrage" });
    }
    return res.status(403).send("Ungültige Anfrage");
  }
  next();
});

app.use(["/login", "/register", "/forgot-password", "/reset-password"], createRateLimiter({
  windowMs: AUTH_RATE_LIMIT_WINDOW_MS,
  max: AUTH_RATE_LIMIT_MAX,
  keyPrefix: "auth",
  message: "Zu viele Versuche. Bitte kurz warten."
}));

app.use([
  "/admin/checkin-scan",
  "/admin/custom-scan",
  "/admin/redeem-scan",
  "/admin/redeem-voucher",
  "/admin/redeem-voucher-code"
], createRateLimiter({
  windowMs: ADMIN_RATE_LIMIT_WINDOW_MS,
  max: ADMIN_RATE_LIMIT_MAX,
  keyPrefix: "admin-flow",
  message: "Zu viele Scan-Anfragen. Bitte kurz warten."
}));

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifySession(token) {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");

  try {
    const sigBuffer = Buffer.from(sig);
    const expectedBuffer = Buffer.from(expected);
    if (sigBuffer.length !== expectedBuffer.length) return null;
    if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) return null;
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function signTimedToken(payload, expiresMinutes = 30) {
  return signSession({
    ...payload,
    exp: Date.now() + Math.max(1, Number(expiresMinutes || 30)) * 60 * 1000
  });
}

function verifyTimedToken(token, expectedPurpose) {
  const payload = verifySession(token);
  if (!payload) return null;
  if (expectedPurpose && payload.purpose !== expectedPurpose) return null;
  if (!payload.exp || Number(payload.exp) < Date.now()) return null;
  return payload;
}

function passwordResetFingerprint(user) {
  return crypto.createHash("sha256").update(String(user?.passwordHash || "")).digest("hex").slice(0, 24);
}

async function getCurrentUser(req) {
  const token = req.cookies[SESSION_COOKIE_NAME] || "";
  const session = verifySession(token);
  if (!session?.userId) return null;

  return prisma.user.findUnique({ where: { id: session.userId } });
}

function isAdmin(user) {
  return !!user && user.role === "admin";
}

function setSession(res, user) {
  res.cookie(
    SESSION_COOKIE_NAME,
    signSession({
      userId: user.id,
      email: user.email,
      role: user.role
    }),
    {
      httpOnly: true,
      sameSite: "lax",
      secure: APP_URL.startsWith("https://") || process.env.NODE_ENV === "production",
      path: "/",
      maxAge: SESSION_MAX_AGE_DAYS * 24 * 60 * 60 * 1000
    }
  );
}

function clearSession(res) {
  res.clearCookie(SESSION_COOKIE_NAME, { path: "/" });
}

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

async function ensureScannerConfig() {
  return prisma.scannerConfig.upsert({
    where: { id: 1 },
    update: {},
    create: {
      id: 1,
      active: true,
      label: "2 Pizzen bestellt",
      addPoints: 15,
      addPizzas: 2,
      oncePerDay: true
    }
  });
}

async function getTaskState(userId, type) {
  return prisma.taskState.upsert({
    where: {
      userId_type: {
        userId,
        type
      }
    },
    update: {},
    create: {
      id: uid(),
      userId,
      type,
      clickedAt: null,
      claimedAt: null,
      status: "idle"
    }
  });
}

async function getOpenVouchers(userId) {
  return prisma.voucher.findMany({
    where: {
      userId,
      status: "open"
    },
    orderBy: { createdAt: "desc" }
  });
}

async function getUserEvents(userId, limit = 20) {
  return prisma.event.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    take: limit
  });
}

async function latestSubmission(userId, type, taskId = null) {
  return prisma.submission.findFirst({
    where: {
      userId,
      type,
      ...(taskId ? { taskId } : {})
    },
    orderBy: { createdAt: "desc" }
  });
}

async function createVoucher(userId, title, source, meta = {}, tx = prisma) {
  const code = `PB-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;

  return tx.voucher.create({
    data: {
      id: uid(),
      userId,
      title,
      source,
      code,
      status: "open",
      createdAt: nowDate(),
      usedAt: null,
      usedBy: null,
      meta
    }
  });
}

async function addEvent(userId, type, points, pizzas, note, meta = {}, tx = prisma) {
  const user = await tx.user.findUnique({ where: { id: userId } });
  if (!user) throw new Error("USER_NOT_FOUND");

  const nextPoints = Math.max(0, Number(user.points || 0) + Number(points || 0));
  const nextPizzaCount = Math.max(0, Number(user.pizzaCount || 0) + Number(pizzas || 0));

  await tx.user.update({
    where: { id: userId },
    data: {
      points: nextPoints,
      pizzaCount: nextPizzaCount
    }
  });

  const event = await tx.event.create({
    data: {
      id: uid(),
      userId,
      type,
      points: Number(points || 0),
      pizzas: Number(pizzas || 0),
      note,
      meta,
      createdAt: nowDate(),
      dayKey: dayKey()
    }
  });

  if (Number(pizzas || 0) > 0) {
    const before = Math.floor(Number(user.pizzaCount || 0) / 10);
    const after = Math.floor(nextPizzaCount / 10);

    for (let i = before + 1; i <= after; i += 1) {
      await createVoucher(userId, "Kostenlose Pizza", "pizza-milestone", { milestone: i * 10 }, tx);
      await tx.event.create({
        data: {
          id: uid(),
          userId,
          type: "pizza-milestone",
          points: 0,
          pizzas: 0,
          note: `Gratis-Pizza für ${i * 10} Pizzen freigeschaltet`,
          meta: { milestone: i * 10 },
          createdAt: nowDate(),
          dayKey: dayKey()
        }
      });
    }
  }

  return event;
}

function assertResendConfigured() {
  if (!RESEND_API_KEY || !process.env.SMTP_FROM) {
    throw new Error("RESEND_NOT_CONFIGURED");
  }
}

async function verifyMailerConnection() {
  try {
    assertResendConfigured();
    console.log("Resend API configured");
  } catch (error) {
    console.error("Resend config check failed", error);
  }
}
function assertRuntimeSecurity() {
  if (process.env.NODE_ENV === "production" && SESSION_SECRET === "change_me_super_secret") {
    throw new Error("SESSION_SECRET must be set in production");
  }

}


async function sendVerificationMail(user, verifyLink) {
  assertResendConfigured();

  const { error } = await resend.emails.send({
    from: process.env.SMTP_FROM,
    to: [user.email],
    subject: `${BRAND_NAME} – E-Mail bestätigen`,
    html: `
      <div style="font-family:Inter,Arial,sans-serif;line-height:1.5;color:#241c16;max-width:580px;margin:0 auto;padding:24px">
        <div style="font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#bf5a34;margin-bottom:8px">${escapeHtml(BRAND_SUBTITLE)}</div>
        <h1 style="margin:0 0 12px;font-size:28px;line-height:1.1">Willkommen bei ${escapeHtml(BRAND_NAME)}</h1>
        <p style="margin:0 0 12px">Hallo ${escapeHtml(user.name)},</p>
        <p style="margin:0 0 20px">bitte bestätige deine E-Mail-Adresse, damit dein Konto aktiviert wird.</p>
        <p style="margin:0 0 20px">
          <a href="${verifyLink}" style="display:inline-block;padding:12px 16px;background:#bf5a34;color:#ffffff;text-decoration:none;border-radius:12px;font-weight:700">E-Mail bestätigen</a>
        </p>
        <p style="margin:0 0 8px;color:#6d6258">Falls der Button nicht funktioniert, nutze diesen Link:</p>
        <p style="margin:0;color:#6d6258;word-break:break-all">${escapeHtml(verifyLink)}</p>
      </div>
    `
  });

  if (error) {
    throw error;
  }
}

async function sendPasswordResetMail(user, resetLink) {
  assertResendConfigured();

  const { error } = await resend.emails.send({
    from: process.env.SMTP_FROM,
    to: [user.email],
    subject: `${BRAND_NAME} – Passwort zurücksetzen`,
    html: `
      <div style="font-family:Inter,Arial,sans-serif;line-height:1.5;color:#241c16;max-width:580px;margin:0 auto;padding:24px">
        <div style="font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#bf5a34;margin-bottom:8px">${escapeHtml(BRAND_SUBTITLE)}</div>
        <h1 style="margin:0 0 12px;font-size:28px;line-height:1.1">Passwort zurücksetzen</h1>
        <p style="margin:0 0 12px">Hallo ${escapeHtml(user.name)},</p>
        <p style="margin:0 0 20px">mit dem Button unten kannst du ein neues Passwort festlegen.</p>
        <p style="margin:0 0 20px">
          <a href="${resetLink}" style="display:inline-block;padding:12px 16px;background:#bf5a34;color:#ffffff;text-decoration:none;border-radius:12px;font-weight:700">Neues Passwort festlegen</a>
        </p>
        <p style="margin:0 0 8px;color:#6d6258">Der Link ist ${PASSWORD_RESET_EXPIRES_MINUTES} Minuten gültig.</p>
        <p style="margin:0;color:#6d6258;word-break:break-all">${escapeHtml(resetLink)}</p>
      </div>
    `
  });

  if (error) {
    throw error;
  }
}

function renderFlash(req) {
  const success = req.query.success ? `<div class="alert success">${escapeHtml(req.query.success)}</div>` : "";
  const error = req.query.error ? `<div class="alert error">${escapeHtml(req.query.error)}</div>` : "";
  return success + error;
}

function brandLogoMarkup() {
  if (!fs.existsSync(brandLogoPath)) return "";
  return `<img src="/brand-logo" alt="${escapeHtml(BRAND_NAME)} Logo" class="brand-logo-img" />`;
}

function nav(user) {
  if (!user) {
    return `
      <a href="/login">Login</a>
      <a href="/register">Mitglied werden</a>
    `;
  }

  return `
    <a href="/account">Konto</a>
    <a href="/wallet">Wallet</a>
    ${isAdmin(user) ? `<a href="/admin">Admin</a>` : ""}
    <form method="post" action="/logout" class="inline-form-nav">
      <button type="submit" class="linklike">Logout</button>
    </form>
  `;
}

function page({ title, user, body, description = "", head = "", pageClass = "" }) {
  const sharedHead = `
    <style>
      :root {
        --bg:#f6f2ed;
        --surface:#fffdfa;
        --surface-2:#fff7f0;
        --surface-3:#fff1e5;
        --line:rgba(119,78,45,.12);
        --line-strong:rgba(119,78,45,.2);
        --text:#221711;
        --muted:#6d5b4f;
        --brand:#bf5a34;
        --brand-strong:#9f4320;
        --success:#2c7a5b;
        --danger:#b54545;
        --shadow:0 20px 48px rgba(45,28,14,.08);
        --shadow-soft:0 12px 28px rgba(45,28,14,.05);
        --radius-xl:28px;
        --radius-lg:22px;
        --radius-md:16px;
        --radius-sm:12px;
      }

      * { box-sizing:border-box; }

      html {
        background:var(--bg);
        color:var(--text);
        -webkit-text-size-adjust:100%;
      }

      body {
        margin:0;
        font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background:
          radial-gradient(circle at top, rgba(191,90,52,.08), transparent 34%),
          linear-gradient(180deg, #faf7f3 0%, #f3eee8 100%);
        color:var(--text);
      }

      a { color:inherit; }

      img { max-width:100%; height:auto; }

      .app-shell {
        width:min(1160px, calc(100% - 28px));
        margin:18px auto;
        min-height:calc(100vh - 36px);
        display:flex;
        flex-direction:column;
        gap:18px;
      }

      .topbar {
        display:flex;
        align-items:center;
        justify-content:space-between;
        gap:18px;
        padding:18px 22px;
        border-radius:var(--radius-xl);
        background:rgba(255,253,250,.88);
        border:1px solid var(--line);
        backdrop-filter:blur(14px);
        box-shadow:var(--shadow-soft);
      }

      .brand.brand-expanded {
        display:flex;
        align-items:center;
        gap:16px;
        min-width:0;
        flex:1 1 auto;
      }

      .brand.brand-expanded .brand-icon {
        width:104px;
        height:82px;
        padding:6px;
        overflow:hidden;
        border-radius:22px;
        background:#fff;
        border:1px solid rgba(119,78,45,.12);
        box-shadow:0 12px 26px rgba(45,28,14,.07);
        display:grid;
        place-items:center;
        flex:0 0 auto;
      }

      .brand.brand-expanded .brand-title {
        font-size:clamp(24px,3vw,34px);
        line-height:1;
        letter-spacing:-.03em;
        font-weight:800;
      }

      .brand.brand-expanded .brand-subtitle {
        margin-top:6px;
        font-size:13px;
        color:var(--muted);
      }

      .brand-logo-img {
        width:100%;
        height:100%;
        object-fit:contain;
        object-position:center;
        display:block;
        border-radius:16px;
      }

      .topnav {
        display:flex;
        justify-content:flex-end;
        align-items:center;
        flex-wrap:wrap;
        gap:10px;
      }

      .topnav a,
      .linklike {
        display:inline-flex;
        align-items:center;
        justify-content:center;
        min-height:42px;
        padding:0 14px;
        border-radius:999px;
        border:1px solid var(--line);
        background:#fff;
        color:var(--text);
        text-decoration:none;
        font-size:14px;
        font-weight:700;
        transition:transform .18s ease, border-color .18s ease, box-shadow .18s ease, background .18s ease;
      }

      .topnav a:hover,
      .linklike:hover,
      .btn:hover {
        transform:translateY(-1px);
        border-color:var(--line-strong);
        box-shadow:0 8px 18px rgba(45,28,14,.08);
      }

      .inline-form-nav {
        margin:0;
      }

      .linklike {
        cursor:pointer;
      }

      .page {
        flex:1 0 auto;
        display:grid;
        gap:18px;
      }

      .page-head {
        padding:0 4px;
      }

      .page-head h1 {
        margin:0 0 8px;
        font-size:clamp(28px,4vw,38px);
        line-height:1.02;
        letter-spacing:-.04em;
      }

      .page-head p {
        margin:0;
        color:var(--muted);
        max-width:62ch;
      }

      .card {
        background:rgba(255,253,250,.95);
        border:1px solid var(--line);
        border-radius:var(--radius-lg);
        padding:22px;
        box-shadow:var(--shadow-soft);
      }

      .form-card {
        display:grid;
        gap:14px;
      }

      h2, h3, h4 {
        margin:0;
        letter-spacing:-.03em;
      }

      p { line-height:1.55; }

      .eyebrow {
        display:inline-flex;
        align-items:center;
        gap:8px;
        margin-bottom:10px;
        color:var(--brand);
        font-size:12px;
        font-weight:800;
        text-transform:uppercase;
        letter-spacing:.12em;
      }

      .muted-text,
      .status-line,
      .list-simple,
      .card p,
      .section-head p {
        color:var(--muted);
      }

      .section-head {
        display:flex;
        align-items:flex-end;
        justify-content:space-between;
        gap:12px;
        margin-bottom:18px;
      }

      .section-head h3 {
        font-size:24px;
      }

      .section-head p {
        margin:0;
        font-size:14px;
      }

      .grid {
        display:grid;
        gap:18px;
      }

      .grid.two {
        grid-template-columns:repeat(2, minmax(0, 1fr));
      }

      .summary-grid,
      .reward-grid {
        display:grid;
        grid-template-columns:repeat(2, minmax(0, 1fr));
        gap:14px;
      }

      .button-row {
        display:flex;
        gap:10px;
        flex-wrap:wrap;
      }

      .btn {
        appearance:none;
        border:none;
        cursor:pointer;
        display:inline-flex;
        align-items:center;
        justify-content:center;
        min-height:46px;
        padding:0 16px;
        border-radius:14px;
        font-weight:800;
        font-size:14px;
        line-height:1;
        text-decoration:none;
        transition:transform .18s ease, box-shadow .18s ease, opacity .18s ease, background .18s ease;
      }

      .btn:disabled {
        opacity:.55;
        cursor:not-allowed;
        transform:none;
        box-shadow:none;
      }

      .btn-primary {
        background:linear-gradient(135deg, var(--brand) 0%, #e58a47 100%);
        color:#fff;
        box-shadow:0 14px 28px rgba(191,90,52,.18);
      }

      .btn-secondary {
        background:#fff;
        color:var(--text);
        border:1px solid var(--line);
      }

      .btn-ghost {
        background:var(--surface-2);
        color:var(--brand-strong);
        border:1px solid rgba(191,90,52,.14);
      }

      label {
        display:grid;
        gap:8px;
        font-size:14px;
        font-weight:700;
      }

      input,
      textarea,
      select {
        width:100%;
        border:1px solid rgba(119,78,45,.18);
        background:#fff;
        border-radius:14px;
        padding:14px 15px;
        font:inherit;
        color:var(--text);
        outline:none;
        transition:border-color .18s ease, box-shadow .18s ease, background .18s ease;
      }

      input:focus,
      textarea:focus,
      select:focus {
        border-color:rgba(191,90,52,.55);
        box-shadow:0 0 0 4px rgba(191,90,52,.12);
      }

      .inline-form {
        display:flex;
        gap:10px;
        align-items:center;
        flex-wrap:wrap;
      }

      .inline-form input {
        flex:1 1 220px;
      }

      .status-line,
      .admin-status-box,
      .empty-state,
      .alert {
        padding:14px 16px;
        border-radius:14px;
        border:1px solid var(--line);
        background:#fff;
      }

      .alert {
        font-weight:700;
      }

      .alert.success {
        background:#eef8f1;
        border-color:rgba(44,122,91,.22);
        color:#255f48;
      }

      .alert.error {
        background:#fff2f2;
        border-color:rgba(181,69,69,.2);
        color:#8f3535;
      }

      .event-list {
        display:grid;
      }

      .event-row {
        display:flex;
        align-items:center;
        justify-content:space-between;
        gap:14px;
        padding:14px 0;
        border-bottom:1px dashed rgba(119,78,45,.18);
      }

      .event-row:last-child {
        border-bottom:none;
        padding-bottom:0;
      }

      .event-row small {
        display:block;
        margin-top:4px;
        color:#8a7b6f;
      }

      .event-side {
        color:var(--brand-strong);
        font-weight:800;
        white-space:nowrap;
      }

      .chip,
      .mini-chip {
        display:inline-flex;
        align-items:center;
        justify-content:center;
        min-height:32px;
        padding:0 12px;
        border-radius:999px;
        background:#fff;
        border:1px solid var(--line);
        color:var(--text);
        font-size:12px;
        font-weight:800;
      }

      .reader {
        width:100%;
        min-height:280px;
        border-radius:18px;
        border:1px dashed rgba(119,78,45,.24);
        background:linear-gradient(180deg,#fff8f2 0%,#fff 100%);
        overflow:hidden;
      }

      .page-footer {
        margin-top:auto;
        padding:10px 4px 4px;
        color:#7b6f64;
        font-size:13px;
      }

      .page-footer a {
        color:var(--brand);
        font-weight:700;
        text-decoration:none;
      }

      .admin-nav-card {
        position: static !important;
        top: auto !important;
      }



      .topbar,
      .card,
      .admin-surface,
      .admin-nav-card {
        background:rgba(255,253,250,.94);
        border-color:rgba(119,78,45,.11);
        box-shadow:0 18px 42px rgba(45,28,14,.065);
      }

      .card {
        transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease;
      }

      .card:hover {
        border-color:rgba(119,78,45,.16);
        box-shadow:0 22px 54px rgba(45,28,14,.08);
      }

      .btn { letter-spacing:-.01em; }

      .btn-primary {
        background:linear-gradient(135deg,#a84522 0%,#d9783f 100%);
        box-shadow:0 10px 22px rgba(191,90,52,.16);
      }

      .btn-secondary,
      .btn-ghost,
      .topnav a,
      .linklike {
        background:rgba(255,255,255,.88);
        border-color:rgba(119,78,45,.14);
      }

      input,
      textarea,
      select { background:rgba(255,255,255,.94); }

      @media (max-width: 920px) {
        .grid.two,
        .summary-grid,
        .reward-grid {
          grid-template-columns:1fr;
        }
      }

      @media (max-width: 760px) {
        .app-shell {
          width:min(100%, calc(100% - 18px));
          margin:10px auto 18px;
          gap:14px;
        }

        .topbar {
          padding:14px;
          flex-direction:column;
          align-items:flex-start;
        }

        .brand.brand-expanded {
          width:100%;
        }

        .brand.brand-expanded .brand-icon {
          width:86px;
          height:68px;
          border-radius:18px;
          padding:5px;
        }

        .brand.brand-expanded .brand-title {
          font-size:clamp(22px,7vw,28px);
        }

        .topnav {
          width:100%;
          justify-content:flex-start;
        }

        .card {
          padding:18px;
          border-radius:18px;
        }

        .button-row,
        .inline-form {
          flex-direction:column;
          align-items:stretch;
        }

        .btn,
        .inline-form input {
          width:100%;
        }

        .section-head {
          flex-direction:column;
          align-items:flex-start;
        }
      }

      @media (max-width: 560px) {
        .topnav a,
        .linklike {
          min-height:40px;
          padding:0 12px;
          font-size:13px;
        }

        .page-head h1 {
          font-size:30px;
        }
      }
    </style>
  `;

  return `<!doctype html>
  <html lang="de">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>${escapeHtml(title)} · ${escapeHtml(BRAND_NAME)}</title>
    <meta name="theme-color" content="#bf5a34" />
    <link rel="stylesheet" href="/static/styles.css" />
    
    ${sharedHead}
    ${head}
  </head>
  <body class="${escapeHtml(pageClass)}">
    <div class="app-shell">
      <header class="topbar">
        <div class="brand brand-expanded">
          <div class="brand-icon">
            ${brandLogoMarkup() || "🍕"}
          </div>
          <div>
            <div class="brand-title">${escapeHtml(BRAND_NAME)}</div>
            <div class="brand-subtitle">${escapeHtml(BRAND_SUBTITLE)}</div>
          </div>
        </div>
        <nav class="topnav">
          ${nav(user)}
        </nav>
      </header>

      <main class="page">
        ${description ? `<section class="page-head"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(description)}</p></section>` : ""}
        ${body}
      </main>

      <footer class="page-footer">
        Kundenkarte, Vorteile & Rewards ·
        <a href="https://www.pizza-berlino.de/" target="_blank" rel="noreferrer">${escapeHtml(BRAND_NAME)}</a>
      </footer>
    </div>
  </body>
  </html>`;
}

function statCard(value, label) {
  return `<div class="stat-card"><strong>${value}</strong><span>${escapeHtml(label)}</span></div>`;
}

function submissionStatusText(s) {
  if (!s) return "Noch nichts gesendet";
  if (s.status === "pending") return "Wird geprüft";
  if (s.status === "approved") return "Freigegeben";
  if (s.status === "rejected") return "Abgelehnt";
  return s.status || "Unbekannt";
}

function submissionLabel(s) {
  if (s.type === "review") return "Google Bewertung";
  if (s.type === "tiktok") return "TikTok Beitrag";
  if (s.type === "custom") return s.note || "Aktion";
  return s.type;
}

async function memberQrDataUrl(user) {
  return QRCode.toDataURL(`lpw:${user.walletToken}`, {
    margin: 1,
    width: 260
  });
}

function resolveRewardAvailability(user) {
  return rewardDefs.map(reward => ({
    ...reward,
    canRedeem: user.points >= reward.cost
  }));
}

function scannerConfigSummary(cfg) {
  return `${cfg.label} · +${cfg.addPoints} Punkte · +${cfg.addPizzas} Pizzen${cfg.oncePerDay ? " · nur 1x täglich" : ""}`;
}

function formatEventSide(event) {
  const parts = [];
  if (event.points) parts.push(`${event.points > 0 ? "+" : ""}${event.points} Pkt`);
  if (event.pizzas) parts.push(`${event.pizzas > 0 ? "+" : ""}${event.pizzas} Pizza`);
  return parts.join(" · ") || "–";
}

function nextRewardProgress(points) {
  const nextReward = rewardDefs.find(r => points < r.cost) || rewardDefs[rewardDefs.length - 1];
  const previousCost = rewardDefs.filter(r => r.cost < nextReward.cost).slice(-1)[0]?.cost || 0;
  const range = Math.max(1, nextReward.cost - previousCost);
  const current = Math.max(0, points - previousCost);
  const pct = Math.max(0, Math.min(100, Math.round((current / range) * 100)));

  return {
    nextReward,
    previousCost,
    pct,
    remaining: Math.max(0, nextReward.cost - points)
  };
}

function nextPizzaProgress(pizzaCount) {
  const nextMilestone = Math.ceil((Math.max(1, pizzaCount + 1)) / 10) * 10;
  const currentBlockStart = Math.floor(pizzaCount / 10) * 10;
  const current = pizzaCount - currentBlockStart;
  const pct = Math.max(0, Math.min(100, Math.round((current / 10) * 100)));

  return {
    nextMilestone,
    pct,
    remaining: Math.max(0, nextMilestone - pizzaCount)
  };
}

function progressBar(percent, fill = "linear-gradient(90deg,#bf5a34 0%,#e28a56 100%)") {
  return `
    <div style="height:10px;background:#efe6db;border-radius:999px;overflow:hidden">
      <div style="width:${percent}%;height:100%;background:${fill};border-radius:999px"></div>
    </div>
  `;
}

function rewardCardProgress(points, cost) {
  return Math.max(0, Math.min(100, Math.round((points / cost) * 100)));
}

function polarToCartesian(centerX, centerY, radius, angleInDegrees) {
  const angleInRadians = ((angleInDegrees - 90) * Math.PI) / 180;
  return {
    x: centerX + radius * Math.cos(angleInRadians),
    y: centerY + radius * Math.sin(angleInRadians)
  };
}

function describeArc(centerX, centerY, radius, startAngle, endAngle) {
  const start = polarToCartesian(centerX, centerY, radius, endAngle);
  const end = polarToCartesian(centerX, centerY, radius, startAngle);
  const largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
  return `M ${start.x} ${start.y} A ${radius} ${radius} 0 ${largeArcFlag} 0 ${end.x} ${end.y}`;
}

function describeSector(centerX, centerY, radius, startAngle, endAngle) {
  const start = polarToCartesian(centerX, centerY, radius, endAngle);
  const end = polarToCartesian(centerX, centerY, radius, startAngle);
  const largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
  return `M ${centerX} ${centerY} L ${start.x} ${start.y} A ${radius} ${radius} 0 ${largeArcFlag} 0 ${end.x} ${end.y} Z`;
}

function pointsArcMarkup(percent, points) {
  const safePercent = Math.max(0, Math.min(100, Number(percent || 0)));
  const endAngle = 180 + safePercent * 1.8;

  return `
    <div class="progress-visual points-visual">
      <svg viewBox="0 0 220 140" aria-hidden="true">
        <defs>
          <linearGradient id="pointsArcGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#bf5a34"></stop>
            <stop offset="100%" stop-color="#ef9d62"></stop>
          </linearGradient>
        </defs>

        <path
          d="${describeArc(110, 110, 78, 180, 360)}"
          fill="none"
          stroke="rgba(191,90,52,.12)"
          stroke-width="14"
          stroke-linecap="round"
        ></path>

        ${
          safePercent > 0
            ? `
              <path
                d="${describeArc(110, 110, 78, 180, endAngle)}"
                fill="none"
                stroke="url(#pointsArcGradient)"
                stroke-width="14"
                stroke-linecap="round"
              ></path>
            `
            : ""
        }
      </svg>

      <div class="progress-center-copy">
        <strong>${points}</strong>
        <span>Punkte</span>
      </div>
    </div>
  `;
}

function pizzaDiagramMarkup(filledSlices, claimReady = false) {
  const safeFilled = Math.max(0, Math.min(10, Number(filledSlices || 0)));

  const segments = Array.from({ length: 10 }, (_, index) => {
    const start = -90 + index * 36 + 2;
    const end = -90 + (index + 1) * 36 - 2;
    const isActive = index < safeFilled;
    const fill = isActive ? (claimReady ? "#2c7a5b" : "#e58a47") : "#f3e7db";

    return `
      <path
        d="${describeSector(110, 110, 82, start, end)}"
        fill="${fill}"
        stroke="#fffaf6"
        stroke-width="3"
      ></path>
    `;
  }).join("");

  return `
    <div class="progress-visual pizza-visual">
      <svg viewBox="0 0 220 220" aria-hidden="true">
        <circle cx="110" cy="110" r="88" fill="#fff6ee"></circle>
        ${segments}
        <circle cx="110" cy="110" r="34" fill="#fffaf6" stroke="rgba(191,90,52,.08)" stroke-width="2"></circle>
        <circle cx="110" cy="110" r="82" fill="none" stroke="rgba(191,90,52,.12)" stroke-width="2"></circle>
      </svg>

      <div class="pizza-center-copy">
        <strong>${safeFilled}/10</strong>
        <span>${claimReady ? "bereit" : "Slices"}</span>
      </div>
    </div>
  `;
}

function pizzaCycleProgress(pizzaCount, claimReady = false) {
  const safeCount = Math.max(0, Number(pizzaCount || 0));
  const filled = claimReady ? 10 : safeCount % 10;

  return {
    filled,
    claimReady,
    remaining: claimReady ? 0 : 10 - filled
  };
}

function taskStateTone(status) {
  if (status === "pending") return "pending";
  if (status === "rejected") return "rejected";
  return "idle";
}

function taskStateLabel(status, idleLabel = "Offen") {
  if (status === "pending") return "Wird geprüft";
  if (status === "rejected") return "Erneut senden";
  return idleLabel;
}

function collapsibleAdminBlock({ id, label = "mehr", content, count = 0, forceCollapse = false, threshold = 0 }) {
  const shouldCollapse = forceCollapse || count >= threshold;
  if (!shouldCollapse) return content;

  return `
    <details class="admin-disclosure" id="${escapeHtml(id)}">
      <summary>${escapeHtml(label)}</summary>
      <div class="admin-disclosure-body">
        ${content}
      </div>
    </details>
  `;
}

async function findUserByWalletPayload(payload) {
  if (!payload.startsWith("lpw:")) return null;
  const walletToken = payload.replace(/^lpw:/, "");
  return prisma.user.findUnique({ where: { walletToken } });
}


async function hasCustomScanAlreadyRun(userId, configHash) {
  const todayEvents = await prisma.event.findMany({
    where: {
      userId,
      type: "staff-scan",
      dayKey: dayKey()
    }
  });

  return todayEvents.some(event => event?.meta?.configHash === configHash);
}

/* ROUTES */

app.get("/", async (req, res) => {
  const user = await getCurrentUser(req);
  if (user) return res.redirect("/account");

  const homeHead = `
    <style>
      .home-page .page {
        display:grid;
        gap:24px;
      }

      .hero-stage {
        display:flex;
        justify-content:center;
      }

      .hero-card-large {
        width:min(100%, 980px);
        min-height:420px;
        padding:56px 34px;
        display:flex;
        flex-direction:column;
        align-items:center;
        justify-content:center;
        text-align:center;
        background:
          radial-gradient(circle at top, rgba(191,90,52,.08), transparent 48%),
          linear-gradient(135deg,#fff8f2 0%,#fffdf9 100%);
        border:1px solid rgba(191,90,52,.12);
        box-shadow:0 18px 40px rgba(56,31,13,.06);
      }

      .hero-card-large h2 {
        margin:0;
        font-size:clamp(36px,6vw,64px);
        line-height:1.02;
        max-width:15ch;
      }

      .hero-card-large p {
        margin:16px 0 0;
        max-width:58ch;
        color:#6e6258;
        font-size:18px;
      }

      .hero-card-large .button-row {
        justify-content:center;
        margin-top:26px;
      }
    </style>
  `;

  const body = `
    <section class="hero-stage">
      <div class="card hero-card hero-card-large">
        <h2>Zeige deine Loyalität bei Pizza Berlino mit unserem Loyalty-Programm.</h2>
        <p>Sammle Punkte im Laden und nutze deine Vorteile direkt in deinem Konto.</p>
        <div class="button-row">
          <a class="btn btn-primary" href="/register">Mitglied werden</a>
          <a class="btn btn-secondary" href="/login">Einloggen</a>
        </div>
      </div>
    </section>
  `;

  res.send(page({
    title: "Willkommen",
    user,
    body,
    head: homeHead,
    pageClass: "home-page"
  }));
});

app.get("/register", async (req, res) => {
  const user = await getCurrentUser(req);
  if (user) return res.redirect("/account");

  const pendingEmail = String(req.query.email || "").trim().toLowerCase();
  const showVerificationState = !!pendingEmail && !!req.query.success;

  const registerHead = `
    <style>
      .register-page .page {
        display:grid;
        gap:20px;
        align-content:start;
      }

      .register-stage {
        display:flex;
        justify-content:center;
        align-items:flex-start;
        flex:0 0 auto;
      }

      .register-card-center {
        width:min(100%, 620px);
        flex:0 0 auto;
        height:auto !important;
        min-height:0 !important;
        align-self:flex-start;
        margin:0;
      }

      .verify-email-chip {
        display:inline-flex;
        align-items:center;
        padding:10px 14px;
        border-radius:999px;
        background:#fff7f1;
        border:1px solid rgba(191,90,52,.12);
        color:#8b4d28;
        font-weight:600;
        word-break:break-all;
      }

      .resend-inline-helper {
        margin-top:16px;
        font-size:12px;
        color:#7b6f64;
      }

      .resend-inline-helper button,
      .mini-resend-form button {
        background:none;
        border:none;
        padding:0;
        color:#9b4d27;
        cursor:pointer;
        font-size:12px;
        font-weight:600;
      }

      .mini-resend-form {
        margin-top:10px;
        display:grid;
        gap:8px;
      }

      .mini-resend-form span {
        font-size:12px;
        color:#7b6f64;
      }
    </style>
  `;

  const body = showVerificationState
    ? `
      ${renderFlash(req)}
      <section class="register-stage">
        <div class="card form-card register-card-center">
          <h3>E-Mail bestätigen</h3>
          <div class="verify-email-chip">${escapeHtml(pendingEmail)}</div>
          <p class="muted-text" style="margin:14px 0 0">Wir haben dir einen Bestätigungslink geschickt. Sobald du bestätigt hast, kannst du dich direkt einloggen.</p>

          <div class="button-row" style="margin-top:18px">
            <a class="btn btn-secondary" href="/login">Zum Login</a>
          </div>

          <form class="mini-resend-form" method="post" action="/resend-verification">
            <input type="hidden" name="email" value="${escapeHtml(pendingEmail)}" />
            <span>Keine Mail erhalten?</span>
            <button type="submit">Neuen Link senden</button>
          </form>
        </div>
      </section>
    `
    : `
      ${renderFlash(req)}
      <section class="register-stage">
        <form class="card form-card register-card-center" method="post" action="/register">
          <h3>Pizza-Berlino-Konto erstellen</h3>
          <label>Name<input name="name" required placeholder="Valentina Rossi" autocomplete="name" /></label>
          <label>E-Mail<input type="email" name="email" required placeholder="kunde@beispiel.de" autocomplete="email" /></label>
          <label>Passwort<input type="password" name="password" required minlength="10" placeholder="Mind. 10 Zeichen, Groß-/Kleinbuchstaben und Zahl" autocomplete="new-password" /></label>
          <button class="btn btn-primary" type="submit">Mitglied werden</button>
        </form>
      </section>
    `;

  res.send(page({
    title: "Mitglied werden",
    user,
    body,
    head: registerHead,
    pageClass: "register-page"
  }));
});

app.post("/register", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  const passwordError = passwordValidationMessage(password);

  if (!name || !email || passwordError) {
    return res.redirect(`/register?error=${encodeURIComponent(passwordError || "Bitte alle Felder korrekt ausfüllen")}`);
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing?.verified) {
    return res.redirect("/register?error=E-Mail+bereits+registriert");
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const verifyToken = DEV_AUTO_VERIFY ? null : uid();

  let user;
  if (existing && !existing.verified) {
    user = await prisma.user.update({
      where: { id: existing.id },
      data: {
        name,
        passwordHash,
        role: ADMIN_EMAILS.has(email) ? "admin" : existing.role,
        verified: DEV_AUTO_VERIFY,
        verifyToken
      }
    });
  } else {
    user = await prisma.user.create({
      data: {
        id: uid(),
        name,
        email,
        passwordHash,
        role: ADMIN_EMAILS.has(email) ? "admin" : "customer",
        verified: DEV_AUTO_VERIFY,
        verifyToken,
        walletToken: `member_${crypto.randomBytes(10).toString("hex")}`,
        points: 0,
        pizzaCount: 0,
        createdAt: nowDate()
      }
    });
  }

  if (DEV_AUTO_VERIFY) {
    return res.redirect("/login?success=Konto+erstellt.+Du+kannst+dich+jetzt+einloggen");
  }

  try {
    const verifyLink = absoluteUrl(`/verify?token=${encodeURIComponent(verifyToken)}`);
    await sendVerificationMail(user, verifyLink);
    return res.redirect(
      existing
        ? `/register?success=Neuer+Bestätigungslink+gesendet&email=${encodeURIComponent(email)}`
        : `/register?success=Bestätigungslink+gesendet&email=${encodeURIComponent(email)}`
    );
  } catch (error) {
    console.error("Verification mail failed", error);
    return res.redirect(`/register?error=Bestätigungsmail+konnte+nicht+gesendet+werden&email=${encodeURIComponent(email)}`);
  }
});

app.post("/resend-verification", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!email) {
    return res.redirect("/register?error=Bitte+eine+E-Mail-Adresse+eingeben");
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return res.redirect(`/register?error=Konto+nicht+gefunden&email=${encodeURIComponent(email)}`);
  }

  if (user.verified) {
    return res.redirect(`/register?success=Diese+E-Mail+ist+bereits+bestätigt&email=${encodeURIComponent(email)}`);
  }

  const verifyToken = uid();
  const updated = await prisma.user.update({
    where: { id: user.id },
    data: { verifyToken }
  });

  try {
    await sendVerificationMail(updated, absoluteUrl(`/verify?token=${encodeURIComponent(verifyToken)}`));
    return res.redirect(`/register?success=Neuer+Bestätigungslink+gesendet&email=${encodeURIComponent(email)}`);
  } catch (error) {
    console.error("Resend verification mail failed", error);
    return res.redirect(`/register?error=Mail+konnte+nicht+gesendet+werden&email=${encodeURIComponent(email)}`);
  }
});

app.get("/verify", async (req, res) => {
  const token = String(req.query.token || "").trim();
  const user = await prisma.user.findFirst({ where: { verifyToken: token } });

  if (!user) {
    return res.redirect("/login?error=Ungültiger+Bestätigungslink");
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      verified: true,
      verifyToken: null
    }
  });

  return res.redirect("/login?success=E-Mail+bestätigt.+Du+kannst+dich+jetzt+einloggen");
});

app.get("/login", async (req, res) => {
  const user = await getCurrentUser(req);
  if (user) return res.redirect("/account");

  const body = `
    ${renderFlash(req)}
    <section class="login-stage">
      <div class="card form-card login-card">
        <h3>Einloggen</h3>
        <form method="post" action="/login">
          <label>E-Mail<input type="email" name="email" required placeholder="kunde@beispiel.de" autocomplete="email" /></label>
          <label>Passwort<input type="password" name="password" required autocomplete="current-password" /></label>
          <div class="form-helper-row"><a href="/forgot-password">Passwort vergessen?</a></div>
          <button class="btn btn-primary" type="submit">Login</button>
        </form>

        <p class="muted-text" style="margin:14px 0 0">
          Noch kein Konto?
          <a href="/register" style="color:#9b4d27;text-decoration:none;font-weight:600">Mitglied werden</a>
        </p>
      </div>
    </section>
  `;

  res.send(page({
    title: "Login",
    user,
    body,
    description: "Mit deinem Pizza-Berlino-Konto anmelden.",
    pageClass: "login-page",
    head: `
      <style>
        .login-page .page {
          display:grid;
          gap:20px;
          align-content:start;
        }

        .login-stage {
          display:flex;
          justify-content:center;
          align-items:flex-start;
          flex:0 0 auto;
        }

        .login-card {
          width:min(100%,560px);
          flex:0 0 auto;
          height:auto !important;
          min-height:0 !important;
          align-self:flex-start;
        }

        .form-helper-row {
          margin:-2px 0 12px;
          display:flex;
          justify-content:flex-end;
        }

        .form-helper-row a {
          color:#9b4d27;
          text-decoration:none;
          font-weight:600;
        }
      </style>
    `
  }));
});

app.post("/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) return res.redirect("/login?error=Ungültige+Zugangsdaten");

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.redirect("/login?error=Ungültige+Zugangsdaten");
  if (!user.verified) return res.redirect("/login?error=Bitte+erst+deine+E-Mail+bestätigen");

  setSession(res, user);
  return res.redirect("/account");
});

app.get("/forgot-password", async (req, res) => {
  const user = await getCurrentUser(req);

  const body = `
    ${renderFlash(req)}
    <section class="grid two">
      <form class="card form-card" method="post" action="/forgot-password">
        <h3>Passwort vergessen</h3>
        <label>E-Mail<input type="email" name="email" required placeholder="kunde@beispiel.de" autocomplete="email" /></label>
        <button class="btn btn-primary" type="submit">Reset-Link senden</button>
      </form>

      <div class="card">
        <h3>Schnell zurück</h3>
        <div class="button-row">
          <a class="btn btn-secondary" href="/login">Zum Login</a>
          ${user ? `<a class="btn btn-ghost" href="/account">Zum Konto</a>` : `<a class="btn btn-ghost" href="/register">Neu registrieren</a>`}
        </div>
      </div>
    </section>
  `;

  res.send(page({
    title: "Passwort vergessen",
    user,
    body,
    description: "Link anfordern und neues Passwort setzen."
  }));
});

app.post("/forgot-password", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();

  if (!email) {
    return res.redirect("/forgot-password?error=Bitte+eine+E-Mail-Adresse+eingeben");
  }

  try {
    assertResendConfigured();
  } catch {
    return res.redirect("/forgot-password?error=Reset-Mail+aktuell+nicht+verfügbar");
  }

  const user = await prisma.user.findUnique({ where: { email } });

  if (user?.verified) {
    const token = signTimedToken({
      purpose: "password-reset",
      userId: user.id,
      email: user.email,
      fp: passwordResetFingerprint(user)
    }, PASSWORD_RESET_EXPIRES_MINUTES);

    const resetLink = absoluteUrl(`/reset-password?token=${encodeURIComponent(token)}`);

    try {
      await sendPasswordResetMail(user, resetLink);
    } catch (error) {
      console.error("Password reset mail failed", error);
    }
  }

  return res.redirect("/forgot-password?success=Wenn+ein+Konto+existiert,+wurde+eine+Mail+gesendet");
});

app.get("/reset-password", async (req, res) => {
  const user = await getCurrentUser(req);
  const token = String(req.query.token || "").trim();
  const payload = verifyTimedToken(token, "password-reset");

  if (!payload?.userId || !payload?.email || !payload?.fp) {
    return res.redirect("/forgot-password?error=Reset-Link+ungültig+oder+abgelaufen");
  }

  const resetUser = await prisma.user.findUnique({ where: { id: payload.userId } });
  if (!resetUser || resetUser.email !== payload.email || passwordResetFingerprint(resetUser) !== payload.fp) {
    return res.redirect("/forgot-password?error=Reset-Link+ungültig+oder+abgelaufen");
  }

  const body = `
    ${renderFlash(req)}
    <section class="grid two">
      <form class="card form-card" method="post" action="/reset-password">
        <h3>Neues Passwort</h3>
        <input type="hidden" name="token" value="${escapeHtml(token)}" />
        <label>Neues Passwort<input type="password" name="password" minlength="10" required autocomplete="new-password" /></label>
        <label>Passwort wiederholen<input type="password" name="passwordConfirm" minlength="10" required autocomplete="new-password" /></label>
        <button class="btn btn-primary" type="submit">Passwort speichern</button>
      </form>

      <div class="card">
        <h3>${escapeHtml(resetUser.email)}</h3>
        <div class="list-simple">
          <div>Link gültig für kurze Zeit</div>
          <div>Mindestens 10 Zeichen</div>
          <div>Groß-/Kleinbuchstaben und Zahl</div>
          <div>Danach direkt einloggen</div>
        </div>
      </div>
    </section>
  `;

  res.send(page({
    title: "Passwort zurücksetzen",
    user,
    body,
    description: "Neues Passwort festlegen."
  }));
});

app.post("/reset-password", async (req, res) => {
  const token = String(req.body.token || "").trim();
  const password = String(req.body.password || "");
  const passwordConfirm = String(req.body.passwordConfirm || "");
  const payload = verifyTimedToken(token, "password-reset");

  if (!payload?.userId || !payload?.email || !payload?.fp) {
    return res.redirect("/forgot-password?error=Reset-Link+ungültig+oder+abgelaufen");
  }

  const passwordError = passwordValidationMessage(password);
  if (passwordError) {
    return res.redirect(`/reset-password?token=${encodeURIComponent(token)}&error=${encodeURIComponent(passwordError)}`);
  }

  if (password !== passwordConfirm) {
    return res.redirect(`/reset-password?token=${encodeURIComponent(token)}&error=Passwörter+stimmen+nicht+überein`);
  }

  const user = await prisma.user.findUnique({ where: { id: payload.userId } });
  if (!user || user.email !== payload.email || passwordResetFingerprint(user) !== payload.fp) {
    return res.redirect("/forgot-password?error=Reset-Link+ungültig+oder+abgelaufen");
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  await prisma.user.update({
    where: { id: user.id },
    data: { passwordHash }
  });

  return res.redirect("/login?success=Passwort+aktualisiert.+Du+kannst+dich+jetzt+einloggen");
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
    getUserEvents(user.id, 10),
    getTaskState(user.id, "instagram"),
    latestSubmission(user.id, "review"),
    latestSubmission(user.id, "tiktok"),
    prisma.customTask.findMany({ where: { active: true }, orderBy: { createdAt: "desc" } })
  ]);

  const rewards = resolveRewardAvailability(user);
  const customTaskSubmissions = await Promise.all(
    customTasks.map(task => latestSubmission(user.id, "custom", task.id))
  );

  const rewardProgress = nextRewardProgress(user.points);
  const pizzaVoucher = vouchers.find(v => v.source === "pizza-milestone");
  const pizzaCycle = pizzaCycleProgress(user.pizzaCount, Boolean(pizzaVoucher));
  const firstName = String(user.name || "").trim().split(/\s+/)[0] || user.name;

  const nextRewardCopy =
    rewardProgress.remaining === 0
      ? `${rewardProgress.nextReward.title} ist bereit.`
      : `Nächster Vorteil: ${rewardProgress.nextReward.title} in ${rewardProgress.remaining} Punkten.`;

  const accountHeroCopy =
    rewardProgress.remaining === 0
      ? `Dein nächster Vorteil ist schon freigeschaltet.`
      : `Du bist ${rewardProgress.remaining} Punkte von ${rewardProgress.nextReward.title} entfernt.`;

  const rewardCardsHtml = rewards.map(reward => {
    return `
      <div class="reward-card ${reward.canRedeem ? "reward-open" : ""}">
        <div class="reward-card-top">
          <strong>${escapeHtml(reward.title)}</strong>
          <span class="reward-cost">ab ${reward.cost} Pkt</span>
        </div>

        <p>${escapeHtml(reward.description)}</p>

        ${progressBar(
          rewardCardProgress(user.points, reward.cost),
          reward.canRedeem
            ? "linear-gradient(90deg,#2c7a5b 0%,#6ac391 100%)"
            : "linear-gradient(90deg,#bf5a34 0%,#e28a56 100%)"
        )}

        <div class="reward-status">
          ${reward.canRedeem ? "Bereit zur Aktivierung" : "Noch gesperrt"}
        </div>

        <form method="post" action="/account/redeem-reward">
          <input type="hidden" name="rewardId" value="${reward.id}" />
          <button
            class="btn ${reward.canRedeem ? "btn-primary" : "btn-ghost"}"
            ${reward.canRedeem ? "" : "disabled"}
            type="submit"
          >
            ${reward.canRedeem ? "Als Gutschein aktivieren" : "Noch nicht verfügbar"}
          </button>
        </form>
      </div>
    `;
  }).join("");

  const vouchersHtml = vouchers.length
    ? `
      <div class="voucher-list">
        ${vouchers.map(v => `
          <div class="voucher-item">
            <div>
              <strong>${escapeHtml(v.title)}</strong>
              <small>${escapeHtml(v.source)}</small>
            </div>
            <div class="voucher-code">${escapeHtml(v.code)}</div>
          </div>
        `).join("")}
      </div>
    `
    : `<p class="muted-text">Keine offenen Gutscheine.</p>`;

  const renderSubmissionTaskCard = ({
    title,
    description,
    submission,
    href,
    hrefLabel,
    formAction,
    placeholder,
    buttonLabel,
    badge = "Offen"
  }) => {
    const status = submission?.status || "idle";
    const statusClass = taskStateTone(status);
    const badgeText = taskStateLabel(status, badge);
    const submittedLink = submission?.link
      ? `<div class="task-link-line"><a href="${escapeHtml(submission.link)}" target="_blank" rel="noreferrer">Link ansehen</a></div>`
      : "";

    if (status === "pending") {
      return `
        <div class="task-card">
          <div class="task-meta">
            <div>
              <strong>${escapeHtml(title)}</strong>
              <p>${escapeHtml(description)}</p>
            </div>
            <span class="task-badge ${statusClass}">${escapeHtml(badgeText)}</span>
          </div>
          ${submittedLink}
        </div>
      `;
    }

    return `
      <div class="task-card">
        <div class="task-meta">
          <div>
            <strong>${escapeHtml(title)}</strong>
            <p>${escapeHtml(description)}</p>
          </div>
          <span class="task-badge ${statusClass}">${escapeHtml(badgeText)}</span>
        </div>

        ${submittedLink}

        ${
          href
            ? `<div class="button-row"><a class="btn btn-ghost" href="${escapeHtml(href)}" target="_blank" rel="noreferrer">${escapeHtml(hrefLabel)}</a></div>`
            : ""
        }

        <form class="inline-form" method="post" action="${formAction}">
          <input name="link" placeholder="${escapeHtml(placeholder)}" required />
          <button class="btn btn-secondary" type="submit">${escapeHtml(buttonLabel)}</button>
        </form>
      </div>
    `;
  };

  const customTaskEntries = customTasks
    .map((task, index) => ({
      task,
      submission: customTaskSubmissions[index]
    }))
    .filter(entry => entry.submission?.status !== "approved");

  const actionCards = [];

  if (!instagramTask.claimedAt) {
    actionCards.push(`
      <div class="task-card task-card-highlight">
        <div class="task-meta">
          <div>
            <strong>Instagram folgen</strong>
            <p>Profil öffnen, kurz dort bleiben und die Punkte laufen automatisch ein.</p>
          </div>
          <span class="task-badge idle">25 Pkt</span>
        </div>

        <div class="button-row">
          <a class="btn btn-primary js-instagram-claim" href="${escapeHtml(INSTAGRAM_URL)}" target="_blank" rel="noreferrer">Profil öffnen</a>
        </div>
      </div>
    `);
  }

  if (reviewSubmission?.status !== "approved") {
    actionCards.push(renderSubmissionTaskCard({
      title: "Google Bewertung",
      description: "Bewertung abgeben und Link einreichen.",
      submission: reviewSubmission,
      href: REVIEW_URL,
      hrefLabel: "Google öffnen",
      formAction: "/tasks/review/submit",
      placeholder: "Dein Bewertungs- oder Profil-Link",
      buttonLabel: reviewSubmission?.status === "rejected" ? "Erneut senden" : "Link senden",
      badge: "Review"
    }));
  }

  if (tiktokSubmission?.status !== "approved") {
    actionCards.push(renderSubmissionTaskCard({
      title: "TikTok Beitrag",
      description: "Link einreichen, danach prüft das Team deinen Beitrag.",
      href: "",
      hrefLabel: "",
      formAction: "/tasks/tiktok",
      placeholder: "https://www.tiktok.com/...",
      buttonLabel: tiktokSubmission?.status === "rejected" ? "Erneut senden" : "Einreichen",
      badge: "50 Pkt"
    }));
  }

  for (const entry of customTaskEntries) {
    actionCards.push(renderSubmissionTaskCard({
      title: entry.task.title,
      description: entry.task.description,
      submission: entry.submission,
      href: entry.task.targetUrl || "",
      hrefLabel: "Aktion öffnen",
      formAction: `/tasks/custom/${entry.task.id}/submit`,
      placeholder: "Dein Link oder Nachweis",
      buttonLabel: entry.submission?.status === "rejected" ? "Erneut senden" : "Einreichen",
      badge: `${entry.task.points} Pkt`
    }));
  }

  const eventsHtml = events.length
    ? `
      <div class="event-list">
        ${events.map(event => `
          <div class="event-row">
            <div>
              <strong>${escapeHtml(event.note)}</strong>
              <small>${formatDateTime(event.createdAt)}</small>
            </div>
            <div class="event-side">${escapeHtml(formatEventSide(event))}</div>
          </div>
        `).join("")}
      </div>
    `
    : `<p class="muted-text">Noch keine Aktivitäten vorhanden.</p>`;

  const accountHead = `
    <style>
      .account-dashboard-page .page {
        display:grid;
        gap:18px;
      }

      .dashboard-hero {
        display:grid;
        grid-template-columns:minmax(0,1fr) minmax(220px,260px);
        gap:18px;
        align-items:center;
        padding:22px;
        background:linear-gradient(135deg,#fff8f2 0%,#fffdf9 100%);
        border:1px solid rgba(191,90,52,.12);
        box-shadow:0 16px 34px rgba(56,31,13,.05);
      }

      .hero-copy h2 {
        margin:4px 0 8px;
        font-size:clamp(28px,4vw,36px);
        line-height:1.05;
      }

      .hero-copy p {
        margin:0;
        color:#6e6258;
        max-width:54ch;
      }

      .hero-qr-shell {
        background:#fff;
        border:1px solid rgba(191,90,52,.12);
        border-radius:22px;
        padding:14px;
        display:grid;
        gap:10px;
        justify-items:center;
        box-shadow:0 10px 24px rgba(56,31,13,.05);
      }

      .hero-qr {
        width:min(220px,100%);
        border-radius:18px;
        background:#fff;
        padding:8px;
      }

      .hero-qr-shell span {
        color:#7b6f64;
        font-size:13px;
      }

      .progress-card {
        border:1px solid rgba(191,90,52,.12);
        box-shadow:0 12px 28px rgba(56,31,13,.04);
      }

      .progress-card-inner {
        display:grid;
        grid-template-columns:minmax(210px,230px) 1fr;
        gap:18px;
        align-items:center;
      }

      .pizza-progress-card .progress-card-inner {
        grid-template-columns:1fr;
        justify-items:center;
      }

      .pizza-progress-card .progress-copy {
        display:grid;
        justify-items:center;
      }

      .progress-visual {
        position:relative;
        width:100%;
        margin-inline:auto;
      }

      .points-visual,
      .pizza-visual {
        max-width:220px;
      }

      .progress-center-copy,
      .pizza-center-copy {
        position:absolute;
        inset:0;
        display:grid;
        place-content:center;
        text-align:center;
        pointer-events:none;
      }

      .progress-center-copy {
        inset:auto 0 10px 0;
      }

      .progress-center-copy strong,
      .pizza-center-copy strong {
        font-size:34px;
        line-height:1;
        color:#2a2019;
      }

      .progress-center-copy span,
      .pizza-center-copy span {
        margin-top:6px;
        font-size:12px;
        color:#7b6f64;
        text-transform:uppercase;
        letter-spacing:.08em;
      }

      .progress-copy h3 {
        margin:0 0 8px;
        font-size:24px;
      }

      .progress-copy p {
        margin:0;
        color:#6e6258;
      }

      .mini-chip {
        display:inline-flex;
        margin-top:12px;
        padding:8px 10px;
        border-radius:999px;
        background:#eef8f1;
        color:#2c7a5b;
        border:1px solid rgba(44,122,91,.16);
        font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
        font-size:13px;
      }

      .mini-note {
        margin-top:12px;
        color:#7a6a5a;
        font-size:14px;
      }

      .reward-card {
        background:#fffaf6;
        border:1px solid rgba(191,90,52,.12);
        border-radius:18px;
        padding:16px;
      }

      .reward-card-top {
        display:flex;
        justify-content:space-between;
        gap:10px;
        align-items:flex-start;
        margin-bottom:8px;
      }

      .reward-card p {
        margin:0 0 12px;
        color:#6e6258;
      }

      .reward-cost {
        flex:0 0 auto;
        padding:6px 10px;
        border-radius:999px;
        background:#fff;
        border:1px solid rgba(191,90,52,.12);
        font-size:13px;
        color:#7b6550;
      }

      .reward-status {
        margin:10px 0 14px;
        color:#7a6858;
        font-size:14px;
      }

      .reward-open {
        background:linear-gradient(180deg,#f5fff9 0%,#fffdfb 100%);
        border-color:rgba(44,122,91,.18);
      }

      .voucher-spotlight {
        margin-bottom:14px;
        padding:14px 16px;
        border-radius:18px;
        background:linear-gradient(135deg,#fff5ea 0%,#fff9f4 100%);
        border:1px solid rgba(191,90,52,.12);
      }

      .voucher-spotlight strong {
        display:block;
        margin-bottom:4px;
      }

      .voucher-spotlight span {
        display:inline-block;
        margin-top:6px;
        padding:6px 10px;
        border-radius:999px;
        background:#fff;
        border:1px solid rgba(191,90,52,.12);
        font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
      }

      .voucher-item {
        display:flex;
        justify-content:space-between;
        align-items:center;
        gap:12px;
        padding:14px 0;
        border-bottom:1px dashed rgba(123,111,100,.22);
      }

      .voucher-item:last-child {
        border-bottom:none;
        padding-bottom:0;
      }

      .voucher-item small {
        display:block;
        margin-top:4px;
        color:#8a7b6f;
      }

      .voucher-code {
        font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
        padding:8px 10px;
        border-radius:12px;
        background:#fff;
        border:1px solid rgba(191,90,52,.12);
        white-space:nowrap;
      }

      .tasks-stack {
        display:grid;
        gap:12px;
      }

      .task-card {
        padding:16px;
        border-radius:18px;
        border:1px solid rgba(191,90,52,.12);
        background:linear-gradient(180deg,#fffaf6 0%,#ffffff 100%);
      }

      .task-card-highlight {
        background:linear-gradient(135deg,#fff3ea 0%,#fffaf6 100%);
      }

      .task-meta {
        display:flex;
        justify-content:space-between;
        gap:12px;
        align-items:flex-start;
      }

      .task-meta strong {
        display:block;
        margin-bottom:4px;
      }

      .task-meta p {
        margin:0;
        color:#6e6258;
      }

      .task-badge {
        flex:0 0 auto;
        display:inline-flex;
        align-items:center;
        justify-content:center;
        min-width:88px;
        padding:8px 10px;
        border-radius:999px;
        font-size:13px;
        font-weight:700;
      }

      .task-badge.idle {
        background:#fff2e8;
        color:#9b4d27;
      }

      .task-badge.pending {
        background:#eef4ff;
        color:#355f9d;
      }

      .task-badge.rejected {
        background:#fff1f1;
        color:#af4c4c;
      }

      .task-link-line {
        margin-top:12px;
      }

      .task-link-line a {
        color:#9b4d27;
        text-decoration:none;
        font-weight:600;
      }

      .empty-state {
        padding:16px;
        border-radius:18px;
        background:linear-gradient(180deg,#f8fcf9 0%,#ffffff 100%);
        border:1px solid rgba(44,122,91,.12);
        color:#2c7a5b;
      }

      .history-card .event-row {
        padding:14px 0;
        align-items:flex-start;
      }

      .history-card .event-row strong {
        display:block;
        margin-bottom:4px;
      }

      .history-card .event-row small {
        color:#8a7b6f;
      }



      .reward-card,
      .reward-card.reward-open {
        position:relative;
        background:#fffdf9;
        border:1px solid rgba(119,78,45,.12);
        box-shadow:0 12px 26px rgba(45,28,14,.045);
      }

      .reward-card::after {
        content:none !important;
        display:none !important;
      }

      .reward-open {
        background:#fffdf9;
        border-color:rgba(119,78,45,.12);
      }

      .reward-card .btn-primary { box-shadow:none; }
      .reward-card .btn-primary:hover { box-shadow:0 8px 18px rgba(45,28,14,.08); }
      .reward-status { color:#6d5b4f; }
      .reward-card form { margin:0; }

      @media (max-width: 920px) {
        .dashboard-hero,
        .progress-card-inner {
          grid-template-columns:1fr;
        }

        .task-meta {
          flex-direction:column;
          align-items:flex-start;
        }
      }
    </style>
  `;

  const body = `
    ${renderFlash(req)}

    <section class="card dashboard-hero">
      <div class="hero-copy">
        <div class="eyebrow">Hi ${escapeHtml(firstName)}</div>
        <h2>Dein Kundenkonto</h2>
        <p>${escapeHtml(accountHeroCopy)}</p>
      </div>

      <div class="hero-qr-shell">
        <img class="hero-qr" src="${qr}" alt="Member QR" />
      </div>
    </section>

    <section class="grid two">
      <div class="card progress-card">
        <div class="section-head">
          <h3>Punkte</h3>
          <p>Dein Fortschritt auf einen Blick.</p>
        </div>

        <div class="progress-card-inner">
          ${pointsArcMarkup(rewardProgress.pct, user.points)}
          <div class="progress-copy">
            <h3>${escapeHtml(rewardProgress.nextReward.title)}</h3>
            <p>${rewardProgress.remaining === 0 ? "Bereit zur Aktivierung." : `Noch ${rewardProgress.remaining} Punkte.`}</p>
          </div>
        </div>
      </div>

      <div class="card progress-card pizza-progress-card">
        <div class="section-head">
          <h3>Gratis-Pizza</h3>
        </div>

        <div class="progress-card-inner">
          ${pizzaDiagramMarkup(pizzaCycle.filled, pizzaCycle.claimReady)}
          ${
            pizzaVoucher
              ? `
                <div class="progress-copy">
                  <span class="mini-chip">${escapeHtml(pizzaVoucher.code)}</span>
                </div>
              `
              : ""
          }
        </div>
      </div>
    </section>

    <section class="grid two" id="rewards">
      <div class="card">
        <div class="section-head">
          <h3>Rewards</h3>
          <p>Aktiviere Vorteile direkt aus deinem Konto.</p>
        </div>

        <div class="reward-grid">
          ${rewardCardsHtml}
        </div>
      </div>

      <div class="card" id="gutscheine">
        <div class="section-head">
          <h3>Gutscheine</h3>
          <p>Im Laden vom Team nach dem Scan eingelöst.</p>
        </div>

        ${
          pizzaVoucher
            ? `
              <div class="voucher-spotlight">
                <strong>Gratis-Pizza freigeschaltet</strong>
                <span>${escapeHtml(pizzaVoucher.code)}</span>
              </div>
            `
            : ""
        }

        ${vouchersHtml}

      </div>
    </section>

    <section class="grid two">
      <div class="card">
        <div class="section-head">
          <h3>Aktionen</h3>
          <p>${actionCards.length ? "Gerade verfügbar." : "Alles erledigt."}</p>
        </div>

        <div class="tasks-stack">
          ${
            actionCards.length
              ? actionCards.join("")
              : `<div class="empty-state">Keine offenen Aktionen.</div>`
          }
        </div>
      </div>

      <div class="card history-card">
        <div class="section-head">
          <h3>Verlauf</h3>
          <p>Zuletzt verbucht.</p>
        </div>

        ${eventsHtml}
      </div>
    </section>
    <script>
      const instagramActionLink = document.querySelector(".js-instagram-claim");
      let instagramActionRunning = false;

      instagramActionLink?.addEventListener("click", async event => {
        event.preventDefault();
        if (instagramActionRunning) return;

        instagramActionRunning = true;
        instagramActionLink.classList.add("is-loading");
        instagramActionLink.textContent = "Wird erfasst...";

        try {
          await fetch("/tasks/instagram/opened", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: ""
          });
        } catch (error) {
          console.error(error);
        }

        const href = instagramActionLink.getAttribute("href") || "";
        const popup = window.open(href, "_blank", "noopener,noreferrer");

        if (!popup) {
          instagramActionRunning = false;
          instagramActionLink.classList.remove("is-loading");
          instagramActionLink.textContent = "Profil öffnen";
          window.location.href = href;
          return;
        }

        window.setTimeout(async () => {
          try {
            const res = await fetch("/tasks/instagram/complete?mode=silent", {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: "",
              keepalive: true
            });

            if (!res.ok) {
              const data = await res.json().catch(() => null);
              const message = data?.error || "Instagram-Aktion konnte nicht abgeschlossen werden";
              window.location.href = "/account?error=" + encodeURIComponent(message);
              return;
            }
          } catch (error) {
            console.error(error);
            window.location.href = "/account?error=Instagram-Aktion+konnte+nicht+abgeschlossen+werden";
            return;
          }

          window.location.href = "/account?success=Instagram+Aktion+abgeschlossen";
        }, ${INSTAGRAM_TASK_SECONDS * 1000});
      });
    </script>
  `;

  res.send(page({
    title: "Kundenkonto",
    user,
    body,
    head: accountHead,
    pageClass: "account-dashboard-page"
  }));
});

app.post("/account/change-password", authRequired, async (req, res) => {
  const user = req.user;
  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");
  const newPasswordConfirm = String(req.body.newPasswordConfirm || "");

  const currentUser = await prisma.user.findUnique({ where: { id: user.id } });
  if (!currentUser) return res.redirect("/account?error=Konto+nicht+gefunden");

  const ok = await bcrypt.compare(currentPassword, currentUser.passwordHash);
  if (!ok) return res.redirect("/account?error=Aktuelles+Passwort+falsch");

  const passwordError = passwordValidationMessage(newPassword);
  if (passwordError) {
    return res.redirect(`/account?error=${encodeURIComponent(passwordError)}`);
  }

  if (newPassword !== newPasswordConfirm) {
    return res.redirect("/account?error=Neue+Passwörter+stimmen+nicht+überein");
  }

  const sameAsOld = await bcrypt.compare(newPassword, currentUser.passwordHash);
  if (sameAsOld) {
    return res.redirect("/account?error=Bitte+ein+anderes+Passwort+verwenden");
  }

  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  const updatedUser = await prisma.user.update({
    where: { id: currentUser.id },
    data: { passwordHash }
  });

  setSession(res, updatedUser);
  return res.redirect("/account?success=Passwort+aktualisiert");
});

app.post("/account/redeem-code", authRequired, async (req, res) => {
  return res.redirect("/account?error=Einlösung+erfolgt+im+Laden+durch+das+Team");
});

app.post("/account/redeem-reward", authRequired, async (req, res) => {
  const user = req.user;
  const rewardId = String(req.body.rewardId || "");
  const reward = rewardDefs.find(r => r.id === rewardId);

  if (!reward) return res.redirect("/account?error=Reward+nicht+gefunden");

  try {
    await prisma.$transaction(async tx => {
      const freshUser = await tx.user.findUnique({ where: { id: user.id } });
      if (!freshUser) throw new Error("USER_NOT_FOUND");
      if (freshUser.points < reward.cost) throw new Error("NOT_ENOUGH_POINTS");

      await addEvent(user.id, "redeem", -reward.cost, 0, `Reward eingelöst: ${reward.title}`, { rewardId }, tx);
      await createVoucher(user.id, reward.title, "points-redeem", { rewardId }, tx);
    });

    res.redirect("/account?success=Reward+eingelöst");
  } catch (error) {
    if (error.message === "NOT_ENOUGH_POINTS") {
      return res.redirect("/account?error=Nicht+genug+Punkte");
    }
    console.error(error);
    res.redirect("/account?error=Reward+konnte+nicht+eingelöst+werden");
  }
});

app.get("/instagram-task", authRequired, async (req, res) => {
  res.redirect("/account");
});

app.post("/tasks/instagram/opened", authRequired, async (req, res) => {
  const task = await getTaskState(req.user.id, "instagram");

  if (task.claimedAt) {
    return res.json({ ok: true, alreadyDone: true });
  }

  await prisma.taskState.update({
    where: { id: task.id },
    data: {
      clickedAt: nowDate(),
      status: "opened"
    }
  });

  res.json({ ok: true });
});

app.post("/tasks/instagram/complete", authRequired, async (req, res) => {
  const user = req.user;
  const task = await getTaskState(user.id, "instagram");
  const silentMode = String(req.query.mode || "") === "silent";

  if (!task.clickedAt) {
    if (silentMode) return res.status(400).json({ ok: false, error: "Instagram wurde noch nicht geöffnet" });
    return res.redirect("/account?error=Instagram+wurde+noch+nicht+gestartet");
  }

  if (task.claimedAt) {
    if (silentMode) return res.json({ ok: true, alreadyDone: true });
    return res.redirect("/account?error=Instagram+bereits+abgeschlossen");
  }

  const secondsSinceOpen = (Date.now() - new Date(task.clickedAt).getTime()) / 1000;
  if (secondsSinceOpen < INSTAGRAM_TASK_SECONDS) {
    if (silentMode) return res.status(400).json({ ok: false, error: "Bitte noch kurz warten" });
    return res.redirect("/account?error=Bitte+noch+kurz+warten");
  }

  await prisma.$transaction(async tx => {
    await tx.taskState.update({
      where: { id: task.id },
      data: {
        claimedAt: nowDate(),
        status: "done"
      }
    });

    await addEvent(user.id, "instagram", 25, 0, "Instagram Profil besucht", { autoClaimed: true }, tx);
  });

  if (silentMode) return res.json({ ok: true });
  res.redirect("/account?success=Instagram+Aktion+abgeschlossen");
});

app.post("/tasks/review/submit", authRequired, async (req, res) => {
  const link = String(req.body.link || "").trim();

  if (!/^https?:\/\//i.test(link)) {
    return res.redirect("/account?error=Bitte+einen+gültigen+Link+eingeben");
  }

  await prisma.submission.create({
    data: {
      id: uid(),
      userId: req.user.id,
      type: "review",
      taskId: null,
      link,
      status: "pending",
      rewardPoints: 0,
      note: "Google Bewertung",
      createdAt: nowDate()
    }
  });

  res.redirect("/account?success=Google-Bewertungs-Link+eingereicht");
});

app.post("/tasks/tiktok", authRequired, async (req, res) => {
  const link = String(req.body.link || "").trim();

  if (!/^https?:\/\//i.test(link)) {
    return res.redirect("/account?error=Bitte+einen+gültigen+Link+eingeben");
  }

  await prisma.submission.create({
    data: {
      id: uid(),
      userId: req.user.id,
      type: "tiktok",
      taskId: null,
      link,
      status: "pending",
      rewardPoints: 50,
      note: "TikTok Beitrag",
      createdAt: nowDate()
    }
  });

  res.redirect("/account?success=TikTok-Link+eingereicht");
});

app.post("/tasks/custom/:taskId/submit", authRequired, async (req, res) => {
  const taskId = String(req.params.taskId || "");
  const link = String(req.body.link || "").trim();
  const task = await prisma.customTask.findFirst({
    where: {
      id: taskId,
      active: true
    }
  });

  if (!task) {
    return res.redirect("/account?error=Task+nicht+gefunden");
  }

  if (!/^https?:\/\//i.test(link)) {
    return res.redirect("/account?error=Bitte+einen+gültigen+Link+eingeben");
  }

  await prisma.submission.create({
    data: {
      id: uid(),
      userId: req.user.id,
      type: "custom",
      taskId: task.id,
      link,
      status: "pending",
      rewardPoints: Number(task.points || 0),
      note: task.title,
      createdAt: nowDate()
    }
  });

  res.redirect("/account?success=Task-Link+eingereicht");
});

app.get("/wallet", authRequired, async (req, res) => {
  const user = req.user;
  const qr = await memberQrDataUrl(user);
  const activeVoucher = (await getOpenVouchers(user.id))[0] || null;

  const body = `
    ${renderFlash(req)}

    <section class="grid two">
      <div class="card">
        <h3>Digitale Kundenkarte</h3>
        <p>Hier findest du deine Karte für Scans im Laden und für deine Wallet.</p>
        <div class="button-row">
          <a class="btn btn-primary" href="/wallet/pass">Wallet Pass laden</a>
          <a class="btn btn-secondary" href="/account">Zurück zum Konto</a>
        </div>
        <div class="status-line">
          ${
            activeVoucher
              ? `Offener Gutschein: <strong>${escapeHtml(activeVoucher.title)}</strong> (${escapeHtml(activeVoucher.code)})`
              : `Aktuell ist kein Gutschein offen`
          }
        </div>
      </div>

      <div class="card center-card">
        <img class="qr-image large" src="${qr}" alt="Wallet QR" />
        <div class="status-line"><code>lpw:${escapeHtml(user.walletToken)}</code></div>
      </div>
    </section>
  `;

  res.send(page({
    title: "Wallet",
    user,
    body,
    description: "Deine Pizza-Berlino-Karte für Punkte, Rewards und Gutscheine."
  }));
});

app.get("/wallet/pass", authRequired, async (req, res) => {
  const user = req.user;

  if (!WALLETWALLET_API_KEY) {
    return res.redirect("/wallet?error=WalletWallet+API-Key+fehlt");
  }

  const activeVoucher = (await getOpenVouchers(user.id))[0] || null;
  const displayValue = activeVoucher ? `${user.name} • ${activeVoucher.title}` : user.name;

  const payload = {
    barcodeValue: `lpw:${user.walletToken}`,
    barcodeFormat: "QR",
    title: BRAND_NAME,
    label: "Mitglied",
    value: displayValue,
    colorPreset: WALLETWALLET_COLOR_PRESET,
    expirationDays: 365
  };

  try {
    const response = await fetch("https://api.walletwallet.dev/api/pkpass", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${WALLETWALLET_API_KEY}`
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const msg = await response.text();
      return res.redirect(`/wallet?error=${encodeURIComponent(`WalletWallet+Fehler:+${msg}`)}`);
    }

    const buffer = Buffer.from(await response.arrayBuffer());
    res.setHeader("Content-Type", "application/vnd.apple.pkpass");
    res.setHeader("Content-Disposition", `attachment; filename="pizza-berlino-${user.id}.pkpass"`);
    res.send(buffer);
  } catch {
    res.redirect("/wallet?error=WalletWallet+Anfrage+fehlgeschlagen");
  }
});

app.get("/staff", adminRequired, (req, res) => {
  res.redirect("/admin#panel-checkin");
});

app.get("/staff/redeem", adminRequired, (req, res) => {
  res.redirect("/admin#panel-voucher");
});

app.post("/admin/checkin-scan", adminRequired, async (req, res) => {
  const payload = String(req.body.payload || "").trim();

  if (!payload.startsWith("lpw:")) return res.status(400).json({ ok: false, error: "Ungültiger QR" });

  const user = await findUserByWalletPayload(payload);
  if (!user) return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });

  if (DAILY_CHECKIN_CONFIG.oncePerDay) {
    const already = await prisma.event.findFirst({
      where: {
        userId: user.id,
        type: "daily-checkin",
        dayKey: dayKey()
      }
    });

    if (already) {
      return res.status(400).json({ ok: false, error: "Heute bereits eingecheckt" });
    }
  }

  await addEvent(
    user.id,
    "daily-checkin",
    DAILY_CHECKIN_CONFIG.addPoints,
    DAILY_CHECKIN_CONFIG.addPizzas,
    DAILY_CHECKIN_CONFIG.label,
    { scannedBy: req.user.email, mode: "checkin" }
  );

  res.json({
    ok: true,
    message: `${DAILY_CHECKIN_CONFIG.label} verbucht`,
    userName: user.name,
    addPoints: DAILY_CHECKIN_CONFIG.addPoints,
    addPizzas: DAILY_CHECKIN_CONFIG.addPizzas
  });
});

app.post("/admin/custom-scan", adminRequired, async (req, res) => {
  const payload = String(req.body.payload || "").trim();
  const cfg = await ensureScannerConfig();

  if (!cfg.active) return res.status(400).json({ ok: false, error: "Scanner deaktiviert" });
  if (!payload.startsWith("lpw:")) return res.status(400).json({ ok: false, error: "Ungültiger QR" });

  const user = await findUserByWalletPayload(payload);
  if (!user) return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });

  const configHash = JSON.stringify({
    label: cfg.label,
    addPoints: cfg.addPoints,
    addPizzas: cfg.addPizzas,
    oncePerDay: cfg.oncePerDay,
    active: cfg.active
  });

  if (cfg.oncePerDay) {
    const already = await hasCustomScanAlreadyRun(user.id, configHash);
    if (already) {
      return res.status(400).json({ ok: false, error: "Heute bereits mit dieser Aktion gescannt" });
    }
  }

  await addEvent(
    user.id,
    "staff-scan",
    Number(cfg.addPoints || 0),
    Number(cfg.addPizzas || 0),
    cfg.label || "Scanner Aktion",
    {
      scannedBy: req.user.email,
      configHash,
      mode: "custom"
    }
  );

  res.json({
    ok: true,
    message: `${cfg.label} verbucht`,
    userName: user.name,
    addPoints: Number(cfg.addPoints || 0),
    addPizzas: Number(cfg.addPizzas || 0)
  });
});

app.post("/admin/redeem-scan", adminRequired, async (req, res) => {
  const payload = String(req.body.payload || "").trim();


  if (!payload.startsWith("lpw:")) {
    return res.status(400).json({ ok: false, error: "Ungültiger QR" });
  }

  const user = await findUserByWalletPayload(payload);
  if (!user) {
    return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });
  }

  const vouchers = await prisma.voucher.findMany({
    where: {
      userId: user.id,
      status: "open"
    },
    orderBy: { createdAt: "desc" }
  });

  res.json({
    ok: true,
    message: vouchers.length ? `${vouchers.length} offene Voucher gefunden` : "Kein offener Voucher vorhanden",
    userName: user.name,
    vouchers: vouchers.map(v => ({
      id: v.id,
      title: v.title,
      code: v.code,
      source: v.source || ""
    }))
  });
});

app.post("/admin/redeem-voucher", adminRequired, async (req, res) => {
  const voucherId = String(req.body.voucherId || "").trim();


  const voucher = await prisma.voucher.findUnique({ where: { id: voucherId } });
  if (!voucher) return res.status(404).json({ ok: false, error: "Voucher nicht gefunden" });
  if (voucher.status !== "open") return res.status(400).json({ ok: false, error: "Voucher bereits eingelöst" });

  const user = await prisma.user.findUnique({ where: { id: voucher.userId } });
  if (!user) return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });

  await prisma.$transaction(async tx => {
    await tx.voucher.update({
      where: { id: voucher.id },
      data: {
        status: "used",
        usedAt: nowDate(),
        usedBy: req.user.email
      }
    });

    await tx.event.create({
      data: {
        id: uid(),
        userId: user.id,
        type: "voucher-used",
        points: 0,
        pizzas: 0,
        note: `Voucher eingelöst: ${voucher.title}`,
        meta: {
          code: voucher.code,
          scannedBy: req.user.email
        },
        createdAt: nowDate(),
        dayKey: dayKey()
      }
    });
  });

  res.json({
    ok: true,
    message: "Voucher eingelöst",
    userName: user.name,
    voucherTitle: voucher.title
  });
});

app.post("/admin/redeem-voucher-code", adminRequired, async (req, res) => {
  const code = normalizeCodeInput(req.body.code || "");


  if (!code) {
    return res.status(400).json({ ok: false, error: "Code fehlt" });
  }

  const voucher = await prisma.voucher.findUnique({ where: { code } });
  if (!voucher) {
    return res.status(404).json({ ok: false, error: "Code nicht gefunden" });
  }

  if (voucher.status !== "open") {
    return res.status(400).json({ ok: false, error: "Code wurde bereits eingelöst" });
  }

  const user = await prisma.user.findUnique({ where: { id: voucher.userId } });
  if (!user) {
    return res.status(404).json({ ok: false, error: "Kunde nicht gefunden" });
  }

  await prisma.$transaction(async tx => {
    await tx.voucher.update({
      where: { id: voucher.id },
      data: {
        status: "used",
        usedAt: nowDate(),
        usedBy: req.user.email
      }
    });

    await tx.event.create({
      data: {
        id: uid(),
        userId: user.id,
        type: "voucher-used",
        points: 0,
        pizzas: 0,
        note: `Voucher eingelöst: ${voucher.title}`,
        meta: {
          code: voucher.code,
          redeemedManuallyBy: req.user.email,
          mode: "manual-code"
        },
        createdAt: nowDate(),
        dayKey: dayKey()
      }
    });
  });

  res.json({
    ok: true,
    message: "Code eingelöst",
    userName: user.name,
    voucherTitle: voucher.title
  });
});

app.get("/admin", adminRequired, async (req, res) => {
  const [
    scannerConfig,
    userCount,
    pendingCount,
    openVoucherCount,
    users,
    pendingSubmissions,
    customTasks,
    recentCodes,
    voucherCounts
  ] = await Promise.all([
    ensureScannerConfig(),
    prisma.user.count(),
    prisma.submission.count({ where: { status: "pending" } }),
    prisma.voucher.count({ where: { status: "open" } }),
    prisma.user.findMany({ orderBy: { createdAt: "desc" } }),
    prisma.submission.findMany({
      where: { status: "pending" },
      include: { user: true },
      orderBy: { createdAt: "desc" }
    }),
    prisma.customTask.findMany({ where: { active: true }, orderBy: { createdAt: "desc" } }),
    prisma.adminCode.findMany({ orderBy: { createdAt: "desc" }, take: 10 }),
    prisma.voucher.groupBy({
      by: ["userId"],
      where: { status: "open" },
      _count: { _all: true }
    })
  ]);

  const voucherCountMap = new Map(voucherCounts.map(entry => [entry.userId, entry._count._all]));

  const pendingSubmissionsHtml = pendingSubmissions.length
    ? pendingSubmissions.map(s => `
        <div class="submission-row">
          <div>
            <strong>${escapeHtml(s.user?.name || "Unbekannt")} · ${escapeHtml(submissionLabel(s))}</strong>
            <p><a href="${escapeHtml(s.link)}" target="_blank" rel="noreferrer">${escapeHtml(s.link)}</a></p>
            <small>${Number(s.rewardPoints || 0)} Punkte</small>
          </div>
          <div class="button-stack">
            <form method="post" action="/admin/submission/${s.id}/approve"><button class="btn btn-primary">Freigeben</button></form>
            <form method="post" action="/admin/submission/${s.id}/reject"><button class="btn btn-ghost">Ablehnen</button></form>
          </div>
        </div>
      `).join("")
    : `<div class="admin-empty">Keine offenen Prüfungen.</div>`;

  const recentCodesHtml = recentCodes.length
    ? `<div class="event-list">${recentCodes.map(c => `
        <div class="event-row">
          <div>
            <strong>${escapeHtml(c.code)}</strong>
            <small>${escapeHtml(c.label)}</small>
          </div>
          <div class="event-side">${c.usedAt ? "eingelöst" : "offen"}</div>
        </div>
      `).join("")}</div>`
    : `<div class="admin-empty">Noch keine Codes.</div>`;

  const usersTableHtml = `
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Punkte</th><th>Pizzen</th><th>Voucher</th></tr>
        </thead>
        <tbody>
          ${users.map(u => `
            <tr>
              <td>
                ${escapeHtml(u.name)}
                <small>${escapeHtml(u.email)}</small>
              </td>
              <td>${u.points}</td>
              <td>${u.pizzaCount}</td>
              <td>${voucherCountMap.get(u.id) || 0}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;

  const adminHead = `
    <style>
      .admin-dashboard-page .page {
        display:grid;
        gap:18px;
      }

      .admin-shell {
        display:grid;
        gap:18px;
      }

      .admin-top-grid {
        display:grid;
        grid-template-columns:1fr;
        gap:18px;
        align-items:stretch;
      }

      .admin-hero-card,
      .admin-surface,
      .admin-list-card,
      .admin-table-card {
        border:1px solid rgba(191,90,52,.12);
        box-shadow:0 14px 32px rgba(56,31,13,.05);
      }

      .admin-hero-card {
        padding:22px;
        background:linear-gradient(135deg,#fff8f2 0%,#fffdf9 100%);
      }

      .admin-hero-copy {
        display:grid;
        gap:16px;
        height:100%;
      }

      .admin-stats-inline {
        display:grid;
        grid-template-columns:repeat(3,minmax(0,1fr));
        gap:12px;
      }

      .admin-stat-box {
        padding:14px 16px;
        border-radius:18px;
        background:#fff;
        border:1px solid rgba(191,90,52,.1);
      }

      .admin-stat-box strong {
        display:block;
        font-size:28px;
        line-height:1;
        margin-bottom:6px;
      }

      .admin-stat-box span {
        color:#76685c;
        font-size:14px;
      }


      .admin-nav-card {
        position: static !important;
        top: auto !important;
        padding: 12px;
        border-radius: 22px;
        background: rgba(255,250,246,.88);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(191,90,52,.12);
        box-shadow: 0 12px 28px rgba(56,31,13,.05);
      }

      .admin-tab-row {
        display:flex;
        flex-wrap:wrap;
        gap:10px;
      }

      .admin-tab-btn {
        min-height:46px;
        padding-inline:16px;
      }

      .admin-panel {
        display:grid;
        gap:18px;
      }

      .admin-grid-two {
        display:grid;
        grid-template-columns:repeat(2,minmax(0,1fr));
        gap:18px;
      }

      .admin-grid-three {
        display:grid;
        grid-template-columns:repeat(3,minmax(0,1fr));
        gap:18px;
      }

      .admin-surface {
        background:#fff;
        border-radius:24px;
        padding:18px;
      }

      .admin-surface .section-head {
        margin-bottom:14px;
      }

      .admin-surface .section-head p {
        margin:0;
      }

      .admin-surface h3,
      .admin-surface h4 {
        margin:0;
      }

      .admin-mini-note {
        display:inline-flex;
        align-items:center;
        gap:8px;
        margin-top:12px;
        padding:8px 10px;
        border-radius:999px;
        background:#fff7f1;
        border:1px solid rgba(191,90,52,.12);
        color:#84553b;
        font-size:13px;
      }

      .admin-status-box {
        margin-top:14px;
        padding:12px 14px;
        border-radius:16px;
        background:#fffaf6;
        border:1px solid rgba(191,90,52,.12);
      }

      .reader {
        min-height:320px;
        border-radius:20px;
        background:
          linear-gradient(180deg,rgba(191,90,52,.03) 0%,rgba(255,255,255,.6) 100%),
          #fffaf6;
        border:1px dashed rgba(191,90,52,.22);
        overflow:hidden;
      }

      .admin-list-card .event-list,
      .admin-table-card .table-wrap,
      .admin-surface .event-list {
        margin-top:10px;
      }

      .submission-row,
      .event-row,
      .action-row {
        display:flex;
        justify-content:space-between;
        gap:14px;
        padding:14px 0;
        border-bottom:1px dashed rgba(123,111,100,.22);
      }

      .submission-row:last-child,
      .event-row:last-child,
      .action-row:last-child {
        border-bottom:none;
        padding-bottom:0;
      }

      .submission-row strong,
      .event-row strong,
      .action-row strong {
        display:block;
        margin-bottom:4px;
      }

      .submission-row p,
      .submission-row small,
      .event-row small,
      .action-row small {
        margin:0;
        color:#7a6d61;
      }

      .submission-row p a,
      .action-row a {
        color:#9b4d27;
        text-decoration:none;
        word-break:break-word;
      }

      .button-stack {
        display:grid;
        gap:8px;
        align-content:start;
      }

      .chip {
        display:inline-flex;
        align-items:center;
        justify-content:center;
        padding:8px 10px;
        border-radius:999px;
        background:#fff7f1;
        border:1px solid rgba(191,90,52,.12);
        color:#84553b;
        font-size:13px;
        white-space:nowrap;
      }

      .voucher-select-grid {
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
        gap:12px;
      }

      .voucher-select-card {
        padding:16px;
        border-radius:18px;
        background:#fffaf6;
        border:1px solid rgba(191,90,52,.12);
        display:grid;
        gap:14px;
      }

      .voucher-select-top {
        display:flex;
        justify-content:space-between;
        gap:12px;
      }

      .voucher-code-line {
        margin-top:6px;
        font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
        color:#2d241d;
      }

      .admin-table-card table {
        width:100%;
        border-collapse:collapse;
      }

      .admin-table-card th,
      .admin-table-card td {
        padding:12px 10px;
        border-bottom:1px solid rgba(123,111,100,.14);
        vertical-align:top;
        text-align:left;
      }

      .admin-table-card th {
        font-size:13px;
        color:#7d7064;
        font-weight:700;
      }

      .admin-table-card td small {
        display:block;
        color:#84776d;
        margin-top:4px;
      }

      .admin-empty {
        padding:16px;
        border-radius:18px;
        background:#fbfaf8;
        border:1px dashed rgba(123,111,100,.22);
        color:#7d7064;
      }

      .scanner-summary-card {
        display:grid;
        gap:14px;
      }

      .admin-compact-form {
        display:grid;
        gap:10px;
      }

      .admin-compact-form .check-row {
        margin-top:2px;
      }

      .admin-inline-top {
        display:flex;
        justify-content:space-between;
        gap:12px;
        align-items:flex-start;
      }

      .admin-disclosure {
        margin-top:10px;
      }

      .admin-disclosure summary {
        display:inline-flex;
        align-items:center;
        cursor:pointer;
        color:#9b4d27;
        font-size:13px;
        font-weight:600;
        list-style:none;
      }

      .admin-disclosure summary::-webkit-details-marker {
        display:none;
      }

      .admin-disclosure[open] summary {
        margin-bottom:12px;
      }

      @media (max-width: 1040px) {
        .admin-top-grid,
        .admin-grid-two,
        .admin-grid-three {
          grid-template-columns:1fr;
        }

        .admin-stats-inline {
          grid-template-columns:1fr;
        }
      }

      @media (max-width: 760px) {
        .admin-tab-row {
          display:grid;
          grid-template-columns:repeat(2,minmax(0,1fr));
          gap:8px;
        }

        .admin-tab-btn {
          width:100%;
          min-height:42px;
          padding-inline:12px;
        }

        .submission-row,
        .event-row,
        .action-row,
        .voucher-select-top,
        .admin-inline-top {
          flex-direction:column;
        }

        .admin-surface,
        .admin-hero-card {
          padding:14px;
          border-radius:18px;
        }
      }
    </style>
  `;

  const body = `
    ${renderFlash(req)}

    <div class="admin-shell">
      <section class="admin-top-grid">
        <div class="card admin-hero-card">
          <div class="admin-hero-copy">
            <div class="admin-stats-inline">
              <div class="admin-stat-box">
                <strong>${userCount}</strong>
                <span>Kunden</span>
              </div>
              <div class="admin-stat-box">
                <strong>${pendingCount}</strong>
                <span>Prüfungen</span>
              </div>
              <div class="admin-stat-box">
                <strong>${openVoucherCount}</strong>
                <span>Voucher offen</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="admin-nav-card">
        <div class="admin-tab-row" id="adminSectionSwitch">
          <button class="btn btn-primary adminTabBtn admin-tab-btn" type="button" data-target="panel-checkin">Check-in</button>
          <button class="btn btn-ghost adminTabBtn admin-tab-btn" type="button" data-target="panel-custom">Scanner</button>
          <button class="btn btn-ghost adminTabBtn admin-tab-btn" type="button" data-target="panel-voucher">Voucher</button>
          <button class="btn btn-ghost adminTabBtn admin-tab-btn" type="button" data-target="panel-managing">Hub</button>
        </div>
      </section>

      <section class="admin-panel" id="panel-checkin">
        <section class="admin-grid-two">
          <div class="card admin-surface">
            <div class="section-head">
              <h3>Check-in</h3>
              <p>Fixe Buchung.</p>
            </div>

            <div class="button-row">
              <button class="btn btn-primary" id="startCheckinScan">Scanner starten</button>
              <button class="btn btn-secondary" id="stopCheckinScan" disabled>Stoppen</button>
            </div>

            <div id="checkinScanStatus" class="admin-status-box">Bereit.</div>
            <div class="admin-mini-note">${escapeHtml(scannerConfigSummary(DAILY_CHECKIN_CONFIG))}</div>
          </div>

          <div class="card admin-surface">
            <div class="section-head">
              <h3>Kamera</h3>
              <p>QR-Code scannen.</p>
            </div>
            <div id="readerCheckin" class="reader"></div>
          </div>
        </section>

        <section class="card admin-surface admin-list-card">
          <div class="section-head">
            <h3>Letzte Check-ins</h3>
            <p>Neueste Buchungen.</p>
          </div>
          <div id="checkinLog" class="event-list"></div>
        </section>
      </section>

      <section class="admin-panel" id="panel-custom" hidden>
        <section class="admin-grid-two">
          <form class="card admin-surface admin-compact-form" method="post" action="/admin/scanner-config">
            <div class="section-head">
              <h3>Scanner Setup</h3>
              <p>Werte für die Buchung.</p>
            </div>

            <label>Label<input name="label" required value="${escapeHtml(scannerConfig.label)}" /></label>
            <label>Punkte<input name="addPoints" type="number" value="${Number(scannerConfig.addPoints || 0)}" /></label>
            <label>Pizzen<input name="addPizzas" type="number" value="${Number(scannerConfig.addPizzas || 0)}" /></label>
            <label class="check-row"><input type="checkbox" name="oncePerDay" ${scannerConfig.oncePerDay ? "checked" : ""} /> Nur 1x pro Tag</label>
            <label class="check-row"><input type="checkbox" name="active" ${scannerConfig.active ? "checked" : ""} /> Aktiv</label>
            <button class="btn btn-primary" type="submit">Speichern</button>
          </form>

          <div class="card admin-surface scanner-summary-card">
            <div class="section-head">
              <h3>Scanner</h3>
              <p>Direkt nutzen.</p>
            </div>

            <div class="admin-mini-note">${escapeHtml(scannerConfigSummary(scannerConfig))}</div>

            <div class="button-row">
              <button class="btn btn-primary" type="button" id="startCustomScan">Scanner starten</button>
              <button class="btn btn-secondary" type="button" id="stopCustomScan" disabled>Stoppen</button>
            </div>

            <div id="customScanStatus" class="admin-status-box">Bereit.</div>
            <div id="readerCustom" class="reader"></div>
          </div>
        </section>

        <section class="admin-grid-two">
          <form class="card admin-surface admin-compact-form" method="post" action="/admin/create-code">
            <div class="section-head">
              <h3>Einmalcode</h3>
              <p>Code für eine spätere Gutschrift anlegen.</p>
            </div>

            <label>Label<input name="label" required placeholder="2 bestellte Pizzen / +25 Punkte" /></label>
            <label>Punkte<input name="addPoints" type="number" value="0" /></label>
            <label>Pizzen<input name="addPizzas" type="number" value="0" /></label>
            <button class="btn btn-secondary" type="submit">Code erzeugen</button>
          </form>

          <div class="card admin-surface admin-list-card">
            <div class="section-head">
              <h3>Letzte Scans</h3>
              <p>Neueste Scanner-Buchungen.</p>
            </div>
            <div id="customScanLog" class="event-list"></div>
          </div>
        </section>

        <section class="admin-grid-two">
          <div class="card admin-surface">
            <div class="section-head">
              <h3>Code manuell einlösen</h3>
              <p>Fallback wenn der Scanner ausfällt.</p>
            </div>

            <div id="adminCodeStatus" class="admin-status-box">Bereit.</div>
            <div class="inline-form" style="margin-top:12px">
              <input id="adminCodeValue" placeholder="z. B. PB-AB12CD" autocomplete="off" />
              <button class="btn btn-primary" type="button" id="applyAdminCodeBtn">Einlösen</button>
            </div>
          </div>

          <div class="card admin-surface">
            <div class="section-head">
              <h3>Hinweis</h3>
              <p>Kein Scan nötig.</p>
            </div>
            <div class="admin-mini-note">Der Code reicht aus.</div>
          </div>
        </section>
      </section>

      <section class="admin-panel" id="panel-voucher" hidden>
        <section class="admin-grid-two">
          <div class="card admin-surface">
            <div class="section-head">
              <h3>Voucher Scan</h3>
              <p>Kunde scannen und Voucher auswählen.</p>
            </div>

            <div class="button-row">
              <button class="btn btn-primary" id="startVoucherScan">Scanner starten</button>
              <button class="btn btn-secondary" id="stopVoucherScan" disabled>Stoppen</button>
            </div>
            <div id="voucherScanStatus" class="admin-status-box">Bereit.</div>
          </div>

          <div class="card admin-surface">
            <div class="section-head">
              <h3>Kamera</h3>
              <p>QR-Code scannen.</p>
            </div>
            <div id="readerVoucher" class="reader"></div>
          </div>
        </section>

        <section class="card admin-surface">
          <div class="section-head">
            <h3>Offene Voucher</h3>
            <p>Nach dem Scan sichtbar.</p>
          </div>
          <div id="voucherSelection"><p class="muted-text">Noch kein Kunde gescannt.</p></div>
        </section>

        <section class="card admin-surface admin-list-card">
          <div class="section-head">
            <h3>Einlösungen</h3>
            <p>Zuletzt verbuchte Voucher.</p>
          </div>
          <div id="voucherLog" class="event-list"></div>
        </section>
      </section>

      <section class="admin-panel" id="panel-managing" hidden>
        <section class="admin-grid-two">
          <form class="card admin-surface admin-compact-form" method="post" action="/admin/custom-tasks">
            <div class="section-head">
              <h3>Neue Aktion</h3>
              <p>Kompakt anlegen.</p>
            </div>

            <label>Titel<input name="title" required placeholder="Like + Kommentar" /></label>
            <label>Beschreibung<input name="description" required placeholder="Kurze Erklärung" /></label>
            <label>Ziel-Link<input name="targetUrl" placeholder="https://instagram.com/..." /></label>
            <label>Punkte<input name="points" type="number" value="20" required /></label>
            <label class="check-row"><input type="checkbox" name="active" checked /> Aktiv</label>
            <button class="btn btn-primary" type="submit">Aktion erstellen</button>
          </form>

          <div class="card admin-surface admin-list-card">
            <div class="section-head">
              <h3>Aktionen</h3>
              <p>Bestehende Aktionen.</p>
            </div>

            ${
              customTasks.length
                ? `<div class="event-list">${customTasks.map(task => `
                    <div class="action-row">
                      <div>
                        <strong>${escapeHtml(task.title)}</strong>
                        <small>${escapeHtml(task.description)}</small>
                        ${task.targetUrl ? `<div><a href="${escapeHtml(task.targetUrl)}" target="_blank" rel="noreferrer">${escapeHtml(task.targetUrl)}</a></div>` : ""}
                      </div>
                      <div class="button-stack">
                        <span class="chip">${task.points} Pkt</span>
                        <form method="post" action="/admin/custom-tasks/${task.id}/toggle">
                          <button class="btn btn-ghost" type="submit">Deaktivieren</button>
                        </form>
                      </div>
                    </div>
                  `).join("")}</div>`
                : `<div class="admin-empty">Noch keine Aktionen erstellt.</div>`
            }
          </div>
        </section>

        <section class="card admin-surface admin-list-card">
          <div class="section-head">
            <h3>Offene Prüfungen</h3>
            <p>Einreichen, prüfen, freigeben.</p>
          </div>

          ${collapsibleAdminBlock({
            id: "pending-submissions-block",
            content: pendingSubmissionsHtml,
            count: pendingSubmissions.length,
            threshold: 5
          })}
        </section>

        <section class="admin-grid-two">
          <div class="card admin-surface admin-list-card">
            <div class="section-head">
              <h3>Einmalcodes</h3>
            </div>
            ${collapsibleAdminBlock({
              id: "recent-codes-block",
              content: recentCodesHtml,
              forceCollapse: true
            })}
          </div>

          <div class="card admin-surface admin-table-card">
            <div class="section-head">
              <h3>Kunden</h3>
            </div>
            ${collapsibleAdminBlock({
              id: "users-table-block",
              content: usersTableHtml,
              forceCollapse: true
            })}
          </div>
        </section>
      </section>
    </div>

    <script src="https://unpkg.com/html5-qrcode"></script>
    <script>
      const panelButtons = Array.from(document.querySelectorAll(".adminTabBtn"));
      const panels = Array.from(document.querySelectorAll(".admin-panel"));
      const scannerState = {};
      let selectedVouchers = [];
      let selectedVoucherUser = "";


      function escapeHtmlClient(value) {
        return String(value).replace(/[&<>"']/g, function (ch) {
          return {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
          }[ch];
        });
      }

      function activatePanel(id) {
        panels.forEach(panel => {
          panel.hidden = panel.id !== id;
        });

        panelButtons.forEach(btn => {
          const active = btn.dataset.target === id;
          btn.classList.toggle("btn-primary", active);
          btn.classList.toggle("btn-ghost", !active);
        });

        window.location.hash = id;
      }

      panelButtons.forEach(btn => {
        btn.addEventListener("click", () => activatePanel(btn.dataset.target));
      });

      const initialHash = window.location.hash?.replace(/^#/, "");
      if (initialHash && document.getElementById(initialHash)) {
        activatePanel(initialHash);
      } else {
        activatePanel("panel-checkin");
      }

      function addLog(logId, html) {
        const logEl = document.getElementById(logId);
        if (!logEl) return;
        logEl.insertAdjacentHTML("afterbegin", "<div class='event-row'>" + html + "</div>");
      }

      async function stopScanner(name, startId, stopId) {
        const current = scannerState[name];
        if (current?.instance && current.running) {
          try { await current.instance.stop(); } catch (e) {}
          try { await current.instance.clear(); } catch (e) {}
        }
        scannerState[name] = { instance: null, running: false };
        const startBtn = document.getElementById(startId);
        const stopBtn = document.getElementById(stopId);
        if (startBtn) startBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = true;
      }

      async function startBasicScanner(options) {
        const {
          name,
          readerId,
          startId,
          stopId,
          statusId,
          logId,
          endpoint,
          successSide
        } = options;

        const startBtn = document.getElementById(startId);
        const stopBtn = document.getElementById(stopId);
        const statusEl = document.getElementById(statusId);

        try {
          if (!window.isSecureContext) {
            statusEl.textContent = "HTTPS oder localhost nötig.";
            return;
          }


          const scanner = new Html5Qrcode(readerId);
          scannerState[name] = { instance: scanner, running: true };

          await scanner.start(
            { facingMode: "environment" },
            { fps: 10, qrbox: { width: 220, height: 220 } },
            async decodedText => {
              if (!scannerState[name]?.running) return;
              scannerState[name].running = false;

              try {
                const form = new URLSearchParams();
                form.set("payload", decodedText);

                const res = await fetch(endpoint, {
                  method: "POST",
                  headers: { "Content-Type": "application/x-www-form-urlencoded" },
                  body: form.toString()
                });

                const data = await res.json();

                if (!res.ok || !data.ok) {
                  statusEl.textContent = data.error || "Fehler";
                  addLog(logId, "<div><strong>Fehler</strong><small>" + escapeHtmlClient(data.error || "Unbekannt") + "</small></div><div class='event-side'>–</div>");
                  await stopScanner(name, startId, stopId);
                  return;
                }

                statusEl.textContent = data.message;
                addLog(
                  logId,
                  "<div><strong>" + escapeHtmlClient(data.userName || "Kunde") + "</strong><small>" + escapeHtmlClient(data.message || "Erfolgreich") + "</small></div><div class='event-side'>" + successSide(data) + "</div>"
                );
                await stopScanner(name, startId, stopId);
              } catch (e) {
                statusEl.textContent = "Scannerfehler";
                await stopScanner(name, startId, stopId);
              }
            }
          );

          startBtn.disabled = true;
          stopBtn.disabled = false;
          statusEl.textContent = "Scanner läuft...";
        } catch (e) {
          statusEl.textContent = "Scanner konnte nicht starten.";
          await stopScanner(name, startId, stopId);
        }
      }

      document.getElementById("startCheckinScan")?.addEventListener("click", () => {
        startBasicScanner({
          name: "checkin",
          readerId: "readerCheckin",
          startId: "startCheckinScan",
          stopId: "stopCheckinScan",
          statusId: "checkinScanStatus",
          logId: "checkinLog",
          endpoint: "/admin/checkin-scan",
          successSide: data => "+" + (data.addPoints || 0)
        });
      });

      document.getElementById("stopCheckinScan")?.addEventListener("click", async () => {
        await stopScanner("checkin", "startCheckinScan", "stopCheckinScan");
        document.getElementById("checkinScanStatus").textContent = "Scanner gestoppt.";
      });

      document.getElementById("startCustomScan")?.addEventListener("click", () => {
        startBasicScanner({
          name: "custom",
          readerId: "readerCustom",
          startId: "startCustomScan",
          stopId: "stopCustomScan",
          statusId: "customScanStatus",
          logId: "customScanLog",
          endpoint: "/admin/custom-scan",
          successSide: data => "+" + (data.addPoints || 0) + " / +" + (data.addPizzas || 0)
        });
      });

      document.getElementById("stopCustomScan")?.addEventListener("click", async () => {
        await stopScanner("custom", "startCustomScan", "stopCustomScan");
        document.getElementById("customScanStatus").textContent = "Scanner gestoppt.";
      });

      document.getElementById("applyAdminCodeBtn")?.addEventListener("click", async () => {
        const statusEl = document.getElementById("adminCodeStatus");
        const codeInput = document.getElementById("adminCodeValue");
        const code = String(codeInput?.value || "").trim().toUpperCase().replace(/\s+/g, "");
        if (!code) {
          statusEl.textContent = "Bitte einen Code eingeben.";
          return;
        }

        const form = new URLSearchParams();
        form.set("code", code);

        const res = await fetch("/admin/redeem-voucher-code", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: form.toString()
        });

        const data = await res.json();
        if (!res.ok || !data.ok) {
          statusEl.textContent = data.error || "Fehler";
          return;
        }

        statusEl.textContent = data.message;
        addLog("voucherLog", "<div><strong>" + escapeHtmlClient(data.userName) + "</strong><small>" + escapeHtmlClient(data.message) + "</small></div><div class='event-side'>" + escapeHtmlClient(data.voucherTitle) + "</div>");
        if (codeInput) codeInput.value = "";
      });

      function renderVoucherSelection(userName, vouchers) {
        const selectionEl = document.getElementById("voucherSelection");
        if (!selectionEl) return;

        if (!vouchers.length) {
          selectionEl.innerHTML = "<p class='muted-text'>Für <strong>" + escapeHtmlClient(userName) + "</strong> ist kein offener Voucher vorhanden.</p>";
          return;
        }

        selectionEl.innerHTML =
          "<div class='voucher-select-grid'>" +
          vouchers.map(v => {
            return (
              "<div class='voucher-select-card'>" +
                "<div class='voucher-select-top'>" +
                  "<div>" +
                    "<strong>" + escapeHtmlClient(v.title) + "</strong>" +
                    "<div class='voucher-code-line'>" + escapeHtmlClient(v.code) + "</div>" +
                    "<small>" + escapeHtmlClient(v.source || "") + "</small>" +
                  "</div>" +
                  "<span class='chip'>offen</span>" +
                "</div>" +
                "<button class='btn btn-primary redeemVoucherBtn' data-voucher-id='" + escapeHtmlClient(v.id) + "'>Einlösen</button>" +
              "</div>"
            );
          }).join("") +
          "</div>";

        document.querySelectorAll(".redeemVoucherBtn").forEach(btn => {
          btn.addEventListener("click", async () => {
            const statusEl = document.getElementById("voucherScanStatus");

            const form = new URLSearchParams();
            form.set("voucherId", btn.getAttribute("data-voucher-id"));
    
            const res = await fetch("/admin/redeem-voucher", {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: form.toString()
            });

            const data = await res.json();
            if (!res.ok || !data.ok) {
              statusEl.textContent = data.error || "Fehler";
              addLog("voucherLog", "<div><strong>Fehler</strong><small>" + escapeHtmlClient(data.error || "Unbekannt") + "</small></div><div class='event-side'>–</div>");
              return;
            }

            statusEl.textContent = data.message;
            addLog("voucherLog", "<div><strong>" + escapeHtmlClient(data.userName) + "</strong><small>" + escapeHtmlClient(data.message) + "</small></div><div class='event-side'>" + escapeHtmlClient(data.voucherTitle) + "</div>");
            selectedVouchers = selectedVouchers.filter(v => v.id !== btn.getAttribute("data-voucher-id"));
            renderVoucherSelection(selectedVoucherUser, selectedVouchers);
          });
        });
      }

      document.getElementById("startVoucherScan")?.addEventListener("click", async () => {
        const startBtn = document.getElementById("startVoucherScan");
        const stopBtn = document.getElementById("stopVoucherScan");
        const statusEl = document.getElementById("voucherScanStatus");

        try {
          if (!window.isSecureContext) {
            statusEl.textContent = "HTTPS oder localhost nötig.";
            return;
          }


          const scanner = new Html5Qrcode("readerVoucher");
          scannerState.voucher = { instance: scanner, running: true };

          await scanner.start(
            { facingMode: "environment" },
            { fps: 10, qrbox: { width: 220, height: 220 } },
            async decodedText => {
              if (!scannerState.voucher?.running) return;
              scannerState.voucher.running = false;

              try {
                const form = new URLSearchParams();
                form.set("payload", decodedText);

                const res = await fetch("/admin/redeem-scan", {
                  method: "POST",
                  headers: { "Content-Type": "application/x-www-form-urlencoded" },
                  body: form.toString()
                });

                const data = await res.json();
                if (!res.ok || !data.ok) {
                  statusEl.textContent = data.error || "Fehler";
                  document.getElementById("voucherSelection").innerHTML = "<p class='muted-text'>" + escapeHtmlClient(data.error || "Fehler") + "</p>";
                  await stopScanner("voucher", "startVoucherScan", "stopVoucherScan");
                  return;
                }

                selectedVoucherUser = data.userName || "";
                selectedVouchers = data.vouchers || [];
                statusEl.textContent = data.message;
                renderVoucherSelection(selectedVoucherUser, selectedVouchers);
                await stopScanner("voucher", "startVoucherScan", "stopVoucherScan");
              } catch (e) {
                statusEl.textContent = "Scannerfehler";
                await stopScanner("voucher", "startVoucherScan", "stopVoucherScan");
              }
            }
          );

          startBtn.disabled = true;
          stopBtn.disabled = false;
          statusEl.textContent = "Scanner läuft...";
        } catch (e) {
          statusEl.textContent = "Scanner konnte nicht starten.";
          await stopScanner("voucher", "startVoucherScan", "stopVoucherScan");
        }
      });

      document.getElementById("stopVoucherScan")?.addEventListener("click", async () => {
        await stopScanner("voucher", "startVoucherScan", "stopVoucherScan");
        document.getElementById("voucherScanStatus").textContent = "Scanner gestoppt.";
      });
    </script>
  `;

  res.send(page({
    title: "Admin",
    user: req.user,
    body,
    head: adminHead,
    pageClass: "admin-dashboard-page"
  }));
});

app.post("/admin/scanner-config", adminRequired, async (req, res) => {
  await prisma.scannerConfig.upsert({
    where: { id: 1 },
    update: {
      active: !!req.body.active,
      label: String(req.body.label || "Scanner Aktion").trim(),
      addPoints: Number(req.body.addPoints || 0),
      addPizzas: Number(req.body.addPizzas || 0),
      oncePerDay: !!req.body.oncePerDay
    },
    create: {
      id: 1,
      active: !!req.body.active,
      label: String(req.body.label || "Scanner Aktion").trim(),
      addPoints: Number(req.body.addPoints || 0),
      addPizzas: Number(req.body.addPizzas || 0),
      oncePerDay: !!req.body.oncePerDay
    }
  });

  res.redirect("/admin?success=Scanner+gespeichert#panel-custom");
});

app.post("/admin/create-code", adminRequired, async (req, res) => {
  const code = normalizeCodeInput(crypto.randomBytes(4).toString("hex").toUpperCase());

  await prisma.adminCode.create({
    data: {
      id: uid(),
      code,
      label: String(req.body.label || "Admin Code").trim(),
      addPoints: Number(req.body.addPoints || 0),
      addPizzas: Number(req.body.addPizzas || 0),
      createdAt: nowDate(),
      createdBy: req.user.email,
      usedAt: null,
      usedByUserId: null
    }
  });

  res.redirect(`/admin?success=${encodeURIComponent(`Code+erstellt:+${code}`)}#panel-custom`);
});

app.post("/admin/custom-tasks", adminRequired, async (req, res) => {
  const title = String(req.body.title || "").trim();
  const description = String(req.body.description || "").trim();
  const targetUrl = String(req.body.targetUrl || "").trim();
  const points = Number(req.body.points || 0);

  if (!title || !description) {
    return res.redirect("/admin?error=Bitte+Titel+und+Beschreibung+angeben#panel-managing");
  }

  await prisma.customTask.create({
    data: {
      id: uid(),
      title,
      description,
      targetUrl: targetUrl || null,
      points,
      active: !!req.body.active,
      createdAt: nowDate(),
      createdBy: req.user.email
    }
  });

  res.redirect("/admin?success=Aktion+erstellt#panel-managing");
});

app.post("/admin/custom-tasks/:id/toggle", adminRequired, async (req, res) => {
  const task = await prisma.customTask.findUnique({ where: { id: req.params.id } });
  if (!task) return res.redirect("/admin?error=Task+nicht+gefunden#panel-managing");

  await prisma.customTask.update({
    where: { id: task.id },
    data: { active: !task.active }
  });

  res.redirect("/admin?success=Aktion+aktualisiert#panel-managing");
});

app.post("/admin/submission/:id/approve", adminRequired, async (req, res) => {
  const submissionId = String(req.params.id || "");

  try {
    await prisma.$transaction(async tx => {
      const submission = await tx.submission.findUnique({ where: { id: submissionId } });
      if (!submission) throw new Error("SUBMISSION_NOT_FOUND");
      if (submission.status !== "pending") throw new Error("SUBMISSION_ALREADY_DONE");

      const user = await tx.user.findUnique({ where: { id: submission.userId } });
      if (!user) throw new Error("USER_NOT_FOUND");

      await tx.submission.update({
        where: { id: submission.id },
        data: {
          status: "approved",
          reviewedAt: nowDate(),
          reviewedBy: req.user.email
        }
      });

      await addEvent(
        user.id,
        submission.type,
        Number(submission.rewardPoints || 0),
        0,
        `${submissionLabel(submission)} freigegeben`,
        { submissionId: submission.id },
        tx
      );
    });

    res.redirect("/admin?success=Submission+freigegeben#panel-managing");
  } catch (error) {
    if (error.message === "SUBMISSION_NOT_FOUND") {
      return res.redirect("/admin?error=Submission+nicht+gefunden#panel-managing");
    }
    if (error.message === "SUBMISSION_ALREADY_DONE") {
      return res.redirect("/admin?error=Submission+bereits+bearbeitet#panel-managing");
    }
    if (error.message === "USER_NOT_FOUND") {
      return res.redirect("/admin?error=Kunde+nicht+gefunden#panel-managing");
    }

    console.error(error);
    res.redirect("/admin?error=Freigabe+fehlgeschlagen#panel-managing");
  }
});

app.post("/admin/submission/:id/reject", adminRequired, async (req, res) => {
  const submission = await prisma.submission.findUnique({ where: { id: req.params.id } });
  if (!submission) return res.redirect("/admin?error=Submission+nicht+gefunden#panel-managing");

  await prisma.submission.update({
    where: { id: submission.id },
    data: {
      status: "rejected",
      reviewedAt: nowDate(),
      reviewedBy: req.user.email
    }
  });

  res.redirect("/admin?success=Submission+abgelehnt#panel-managing");
});

app.get("/health", async (req, res) => {
  const users = await prisma.user.count();
  res.json({
    ok: true,
    app: BRAND_NAME,
    users
  });
});

app.listen(PORT, "0.0.0.0", async () => {
  try {
    assertRuntimeSecurity();
    await ensureScannerConfig();
  } catch (error) {
    console.error("Scanner config bootstrap failed", error);
  }

  if (!DEV_AUTO_VERIFY) {
    await verifyMailerConnection();
  }

  console.log(`${BRAND_NAME} läuft auf ${APP_URL}`);
});
