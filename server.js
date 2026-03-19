import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import QRCode from "qrcode";
import nodemailer from "nodemailer";
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
app.use(express.json());
app.use(cookieParser());
app.use("/static", express.static(path.join(__dirname, "public")));

const DEV_AUTO_VERIFY = process.env.DEV_AUTO_VERIFY === "true";
const PORT = Number(process.env.PORT || 3000);

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
const BRAND_SUBTITLE = process.env.BRAND_SUBTITLE || "Rewards & Vorteile";
const BRAND_LOGO_FILENAME = process.env.BRAND_LOGO_FILENAME || "1773058332279.jfif";
const brandLogoPath = path.join(__dirname, BRAND_LOGO_FILENAME);
const SESSION_SECRET = process.env.SESSION_SECRET || "change_me_super_secret";
const STAFF_PIN = process.env.STAFF_PIN || "2468";

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

const DAILY_CHECKIN_CONFIG = {
  label: "Daily Check-in",
  addPoints: 10,
  addPizzas: 0,
  oncePerDay: true
};

const rewardDefs = [
  { id: "r15", title: "10% Rabatt", cost: 15, description: "10% Rabatt auf die nächste Bestellung." },
  { id: "r50", title: "Kostenloses Getränk", cost: 50, description: "Ein Getränk gratis." },
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

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifySession(token) {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  if (sig !== expected) return null;

  try {
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

async function getCurrentUser(req) {
  const token = req.cookies.session || "";
  const session = verifySession(token);
  if (!session?.userId) return null;

  return prisma.user.findUnique({ where: { id: session.userId } });
}

function isAdmin(user) {
  return !!user && user.role === "admin";
}

function setSession(res, user) {
  res.cookie(
    "session",
    signSession({
      userId: user.id,
      email: user.email,
      role: user.role
    }),
    {
      httpOnly: true,
      sameSite: "lax",
      secure: APP_URL.startsWith("https://") || process.env.NODE_ENV === "production"
    }
  );
}

function clearSession(res) {
  res.clearCookie("session");
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

let mailer = null;

function createMailer() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS || !process.env.SMTP_FROM) {
    throw new Error("SMTP_NOT_CONFIGURED");
  }

  if (mailer) return mailer;

  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || "false") === "true",
    connectionTimeout: Number(process.env.SMTP_CONNECTION_TIMEOUT || 10000),
    greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT || 10000),
    socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT || 15000),
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  return mailer;
}

async function verifyMailerConnection() {
  try {
    await createMailer().verify();
    console.log("SMTP connection verified");
  } catch (error) {
    console.error("SMTP verify failed", error);
  }
}

async function sendVerificationMail(user, verifyLink) {
  const transporter = createMailer();

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: user.email,
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
}

function renderFlash(req) {
  const success = req.query.success ? `<div class="alert success">${escapeHtml(req.query.success)}</div>` : "";
  const error = req.query.error ? `<div class="alert error">${escapeHtml(req.query.error)}</div>` : "";
  return success + error;
}

function brandLogoMarkup(size = 44) {
  if (!fs.existsSync(brandLogoPath)) return "";
  return `<img src="/brand-logo" alt="${escapeHtml(BRAND_NAME)} Logo" style="width:${size}px;height:${size}px;object-fit:cover;border-radius:14px;display:block" />`;
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
  return `<!doctype html>
  <html lang="de">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>${escapeHtml(title)} · ${escapeHtml(BRAND_NAME)}</title>
    <meta name="theme-color" content="#bf5a34" />
    <link rel="stylesheet" href="/static/styles.css" />
    ${head}
  </head>
  <body class="${escapeHtml(pageClass)}">
    <div class="app-shell">
      <header class="topbar">
        <div class="brand">
          <div class="brand-icon" style="padding:0;overflow:hidden;background:#fff7f1">
            ${brandLogoMarkup(48) || "🍕"}
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

      <footer style="margin-top:18px;padding:12px 2px 4px;color:#7b6f64;font-size:13px">
        ${escapeHtml(BRAND_NAME)} · Kundenkarte, Vorteile & Rewards
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

async function findUserByWalletPayload(payload) {
  if (!payload.startsWith("lpw:")) return null;
  const walletToken = payload.replace(/^lpw:/, "");
  return prisma.user.findUnique({ where: { walletToken } });
}

function assertStaffPin(pin) {
  return String(pin || "").trim() === STAFF_PIN;
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

  const body = `
    <section class="grid two">
      <div class="card hero-card" style="position:relative;overflow:hidden">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">
          <div style="width:52px;height:52px;border-radius:16px;overflow:hidden;background:#fff7f1;display:grid;place-items:center;border:1px solid rgba(0,0,0,.06)">
            ${brandLogoMarkup(52) || "🍕"}
          </div>
          <div class="hero-kicker">${escapeHtml(BRAND_NAME)}</div>
        </div>
        <h2>Treue, die man sehen und direkt nutzen kann.</h2>
        <p>Mit deiner Pizza-Berlino-Karte sammelst du Punkte im Laden, verfolgst deinen Fortschritt und löst Vorteile direkt ein.</p>
        <div class="button-row">
          <a class="btn btn-primary" href="/register">Mitglied werden</a>
          <a class="btn btn-secondary" href="/login">Einloggen</a>
        </div>
      </div>

      <div class="card">
        <div class="section-head">
          <h3>So funktioniert’s</h3>
          <p>Klar, schnell und ohne unnötige Schritte.</p>
        </div>
        <div class="list-simple">
          <div>
            <strong>1. Konto erstellen</strong><br />
            <span class="muted-text">Registrieren und E-Mail bestätigen.</span>
          </div>
          <div>
            <strong>2. Karte scannen lassen</strong><br />
            <span class="muted-text">Beim Besuch Punkte oder Pizzen sammeln.</span>
          </div>
          <div>
            <strong>3. Vorteile nutzen</strong><br />
            <span class="muted-text">Rewards und Gutscheine direkt im Konto sehen und einlösen.</span>
          </div>
        </div>
      </div>
    </section>

    <section class="summary-grid">
      ${statCard("10", "Punkte pro Daily Check-in")}
      ${statCard("15", "Punkte bis 10% Rabatt")}
      ${statCard("10", "Pizzen bis Gratis-Pizza")}
    </section>
  `;

  res.send(page({
    title: "Willkommen",
    user,
    body,
    description: "Das Treueprogramm von Pizza Berlino."
  }));
});

app.get("/register", async (req, res) => {
  const user = await getCurrentUser(req);
  if (user) return res.redirect("/account");

  const body = `
    ${renderFlash(req)}
    <section class="grid two">
      <form class="card form-card" method="post" action="/register">
        <h3>Pizza-Berlino-Konto erstellen</h3>
        <label>Name<input name="name" required placeholder="Valentina Rossi" /></label>
        <label>E-Mail<input type="email" name="email" required placeholder="kunde@beispiel.de" /></label>
        <label>Passwort<input type="password" name="password" required minlength="6" placeholder="Mind. 6 Zeichen" autocomplete="new-password" /></label>
        <button class="btn btn-primary" type="submit">Mitglied werden</button>
      </form>

      <div class="card">
        <h3>Deine Vorteile</h3>
        <div class="list-simple">
          <div>Kundenkarte mit QR-Code</div>
          <div>Punkte- und Pizza-Fortschritt</div>
          <div>Direkt sichtbare Rewards</div>
          <div>Offene Gutscheine im Konto</div>
        </div>
      </div>
    </section>
  `;

  res.send(page({
    title: "Mitglied werden",
    user,
    body,
    description: "Registrieren, bestätigen und direkt loslegen."
  }));
});

app.post("/register", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!name || !email || password.length < 6) {
    return res.redirect("/register?error=Bitte+alle+Felder+korrekt+ausfüllen");
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing?.verified) {
    return res.redirect("/register?error=E-Mail+bereits+registriert");
  }

  const passwordHash = await bcrypt.hash(password, 10);
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
        ? "/login?success=Bestätigungslink+erneut+gesendet"
        : "/login?success=Konto+erstellt.+Bitte+E-Mail+bestätigen"
    );
  } catch (error) {
    console.error("Verification mail failed", error);
    return res.redirect("/login?error=Bestätigungsmail+konnte+nicht+gesendet+werden.+Bitte+über+Login+erneut+anfordern");
  }
});

app.post("/resend-verification", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!email) {
    return res.redirect("/login?error=Bitte+eine+E-Mail-Adresse+eingeben");
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return res.redirect("/login?error=Konto+nicht+gefunden");
  }

  if (user.verified) {
    return res.redirect("/login?success=Diese+E-Mail+ist+bereits+bestätigt");
  }

  const verifyToken = uid();
  const updated = await prisma.user.update({
    where: { id: user.id },
    data: { verifyToken }
  });

  try {
    await sendVerificationMail(updated, absoluteUrl(`/verify?token=${encodeURIComponent(verifyToken)}`));
    return res.redirect("/login?success=Bestätigungslink+erneut+gesendet");
  } catch (error) {
    console.error("Resend verification mail failed", error);
    return res.redirect("/login?error=Mail+konnte+nicht+gesendet+werden");
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
    <section class="grid two">
      <form class="card form-card" method="post" action="/login">
        <h3>Einloggen</h3>
        <label>E-Mail<input type="email" name="email" required placeholder="kunde@beispiel.de" /></label>
        <label>Passwort<input type="password" name="password" required autocomplete="current-password" /></label>
        <button class="btn btn-primary" type="submit">Login</button>
      </form>

      <form class="card form-card" method="post" action="/resend-verification">
        <h3>Bestätigungslink erneut senden</h3>
        <p>Falls deine E-Mail noch nicht angekommen ist, kannst du hier einen neuen Link anfordern.</p>
        <label>E-Mail<input type="email" name="email" required placeholder="kunde@beispiel.de" /></label>
        <button class="btn btn-secondary" type="submit">Link anfordern</button>
      </form>
    </section>
  `;

  res.send(page({
    title: "Login",
    user,
    body,
    description: "Mit deinem Pizza-Berlino-Konto anmelden."
  }));
});

app.post("/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) return res.redirect("/login?error=Konto+nicht+gefunden");

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.redirect("/login?error=Falsches+Passwort");
  if (!user.verified) return res.redirect("/login?error=Bitte+erst+deine+E-Mail+bestätigen");

  setSession(res, user);
  return res.redirect("/account");
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
      : `Noch ${rewardProgress.remaining} Punkte bis ${rewardProgress.nextReward.title}.`;

  const rewardCardsHtml = rewards.map(reward => {
    const remaining = Math.max(0, reward.cost - user.points);

    return `
      <div class="reward-card ${reward.canRedeem ? "reward-open" : ""}">
        <div class="reward-card-top">
          <strong>${escapeHtml(reward.title)}</strong>
          <span class="reward-cost">${reward.cost} Pkt</span>
        </div>

        <p>${escapeHtml(reward.description)}</p>

        ${progressBar(
          rewardCardProgress(user.points, reward.cost),
          reward.canRedeem
            ? "linear-gradient(90deg,#2c7a5b 0%,#6ac391 100%)"
            : "linear-gradient(90deg,#bf5a34 0%,#e28a56 100%)"
        )}

        <div class="reward-status">
          ${reward.canRedeem ? "Jetzt einlösbar" : `${remaining} Punkte fehlen`}
        </div>

        <form method="post" action="/account/redeem-reward">
          <input type="hidden" name="rewardId" value="${reward.id}" />
          <button
            class="btn ${reward.canRedeem ? "btn-primary" : "btn-ghost"}"
            ${reward.canRedeem ? "" : "disabled"}
            type="submit"
          >
            ${reward.canRedeem ? "Einlösen" : "Noch nicht verfügbar"}
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
            <p>5 Sekunden öffnen, dann werden die Punkte automatisch gutgeschrieben.</p>
          </div>
          <span class="task-badge idle">25 Pkt</span>
        </div>

        <div class="button-row">
          <a class="btn btn-primary" href="/instagram-task">Starten</a>
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
      submission: tiktokSubmission,
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

      @media (max-width: 920px) {
        .dashboard-hero,
        .progress-card-inner {
          grid-template-columns:1fr;
        }

        .task-meta {
          flex-direction:column;
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
        <p>${escapeHtml(nextRewardCopy)}</p>

        <div class="button-row" style="margin-top:16px">
          <a class="btn btn-primary" href="/wallet">Wallet öffnen</a>
          <a class="btn btn-secondary" href="#rewards">Rewards</a>
        </div>
      </div>

      <div class="hero-qr-shell">
        <img class="hero-qr" src="${qr}" alt="Member QR" />
        <span>Zum Scannen im Laden</span>
      </div>
    </section>

    <section class="grid two">
      <div class="card progress-card">
        <div class="section-head">
          <h3>Punkte</h3>
          <p>${escapeHtml(nextRewardCopy)}</p>
        </div>

        <div class="progress-card-inner">
          ${pointsArcMarkup(rewardProgress.pct, user.points)}
          <div class="progress-copy">
            <h3>${escapeHtml(rewardProgress.nextReward.title)}</h3>
            <p>${rewardProgress.remaining === 0 ? "Jetzt einlösbar." : `${rewardProgress.remaining} Punkte fehlen.`}</p>
          </div>
        </div>
      </div>

      <div class="card progress-card">
        <div class="section-head">
          <h3>Gratis-Pizza</h3>
          <p>${pizzaVoucher ? "Gutschein ist bereit." : `${pizzaCycle.remaining} ${pizzaCycle.remaining === 1 ? "Pizza" : "Pizzen"} bis zum Gutschein.`}</p>
        </div>

        <div class="progress-card-inner">
          ${pizzaDiagramMarkup(pizzaCycle.filled, pizzaCycle.claimReady)}
          <div class="progress-copy">
            <h3>${pizzaVoucher ? "Bereit zum Einlösen" : "1 Slice = 1 Pizza"}</h3>
            ${
              pizzaVoucher
                ? `<span class="mini-chip">${escapeHtml(pizzaVoucher.code)}</span>`
                : `<div class="mini-note">Bis 10/10 sammeln.</div>`
            }
          </div>
        </div>
      </div>
    </section>

    <section class="grid two" id="rewards">
      <div class="card">
        <div class="section-head">
          <h3>Rewards</h3>
          <p>Mit Punkten freischalten.</p>
        </div>

        <div class="reward-grid">
          ${rewardCardsHtml}
        </div>
      </div>

      <div class="card" id="gutscheine">
        <div class="section-head">
          <h3>Gutscheine &amp; Codes</h3>
          <p>Direkt nutzbar im Shop.</p>
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

        <div class="task-block" style="margin-top:16px">
          <div>
            <strong>Code einlösen</strong>
            <p class="muted-text">Falls dir ein Code gegeben wurde.</p>
          </div>
          <form class="inline-form" method="post" action="/account/redeem-code">
            <input name="code" placeholder="z. B. PB-AB12CD" required />
            <button class="btn btn-secondary" type="submit">Einlösen</button>
          </form>
        </div>
      </div>
    </section>

    <section class="grid two">
      <div class="card">
        <div class="section-head">
          <h3>Aktionen</h3>
          <p>${actionCards.length ? "Offene Aufgaben." : "Alles erledigt."}</p>
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
          <p>Letzte Buchungen.</p>
        </div>

        ${eventsHtml}
      </div>
    </section>
  `;

  res.send(page({
    title: "Kundenkonto",
    user,
    body,
    head: accountHead,
    pageClass: "account-dashboard-page"
  }));
});

app.post("/account/redeem-code", authRequired, async (req, res) => {
  const user = req.user;
  const code = String(req.body.code || "").trim().toUpperCase();

  const ownVoucher = await prisma.voucher.findFirst({
    where: {
      code,
      userId: user.id,
      status: "open"
    }
  });

  if (ownVoucher) {
    await prisma.$transaction(async tx => {
      await tx.voucher.update({
        where: { id: ownVoucher.id },
        data: {
          status: "used",
          usedAt: nowDate()
        }
      });

      await tx.event.create({
        data: {
          id: uid(),
          userId: user.id,
          type: "voucher-used-manual",
          points: 0,
          pizzas: 0,
          note: `Voucher verwendet: ${ownVoucher.title}`,
          meta: { code },
          createdAt: nowDate(),
          dayKey: dayKey()
        }
      });
    });

    return res.redirect("/account?success=Voucher+verwendet");
  }

  const foreignVoucher = await prisma.voucher.findUnique({ where: { code } });
  if (foreignVoucher && foreignVoucher.userId !== user.id) {
    return res.redirect("/account?error=Dieser+Voucher+gehört+zu+einem+anderen+Konto");
  }

  const adminCode = await prisma.adminCode.findUnique({ where: { code } });
  if (!adminCode || adminCode.usedAt) {
    return res.redirect("/account?error=Code+nicht+gefunden");
  }

  await prisma.$transaction(async tx => {
    await tx.adminCode.update({
      where: { id: adminCode.id },
      data: {
        usedAt: nowDate(),
        usedByUserId: user.id
      }
    });

    await addEvent(
      user.id,
      "admin-code",
      Number(adminCode.addPoints || 0),
      Number(adminCode.addPizzas || 0),
      adminCode.label || "Admin Code",
      { code: adminCode.code },
      tx
    );
  });

  res.redirect("/account?success=Code+eingelöst");
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
  const user = req.user;
  const ig = await getTaskState(user.id, "instagram");

  const head = `
    <style>
      .instagram-task-page .page {
        display:grid;
        gap:18px;
      }

      .insta-flow-card {
        border:1px solid rgba(191,90,52,.12);
        box-shadow:0 14px 34px rgba(56,31,13,.05);
      }

      .countdown-orb {
        width:132px;
        height:132px;
        border-radius:50%;
        margin:18px auto 16px;
        display:grid;
        place-items:center;
        text-align:center;
        background:
          radial-gradient(circle at 50% 50%, #fff 0 42%, transparent 43%),
          conic-gradient(from 180deg, #bf5a34, #ef9d62, #ffd2b3, #bf5a34);
        box-shadow:0 16px 34px rgba(191,90,52,.14);
      }

      .countdown-inner {
        width:88px;
        height:88px;
        border-radius:50%;
        background:#fffaf6;
        display:grid;
        place-items:center;
        box-shadow:inset 0 0 0 1px rgba(191,90,52,.08);
      }

      .countdown-inner strong {
        display:block;
        font-size:34px;
        line-height:1;
        color:#2a2019;
      }

      .countdown-inner span {
        display:block;
        margin-top:4px;
        color:#7b6f64;
        font-size:11px;
        text-transform:uppercase;
        letter-spacing:.08em;
      }
    </style>
  `;

  const body = `
    ${renderFlash(req)}

    <section class="grid two">
      <div class="card insta-flow-card">
        <div class="eyebrow">Instagram Aktion</div>
        <h2 style="margin:6px 0 8px">
          ${ig.claimedAt ? "Schon erledigt" : "5 Sekunden, dann Punkte"}
        </h2>

        <p style="margin:0;color:#6e6258">
          ${
            ig.claimedAt
              ? "Diese Aktion wurde bereits abgeschlossen."
              : "Instagram wird geöffnet und danach automatisch abgeschlossen."
          }
        </p>

        <div class="countdown-orb">
          <div class="countdown-inner">
            <div>
              <strong id="countdownValue">${ig.claimedAt ? "✓" : "5"}</strong>
              <span>${ig.claimedAt ? "erledigt" : "Sekunden"}</span>
            </div>
          </div>
        </div>

        <div id="taskStatus" class="status-line">
          ${ig.claimedAt ? "Aktion bereits abgeschlossen." : "Bereit."}
        </div>

        <div class="button-row" style="margin-top:16px">
          ${
            ig.claimedAt
              ? `<a class="btn btn-primary" href="/account">Zurück</a>`
              : `
                <button class="btn btn-primary" id="openInstagram">Instagram öffnen</button>
                <a class="btn btn-secondary" href="/account">Abbrechen</a>
              `
          }
        </div>
      </div>

      <div class="card insta-flow-card">
        <h3>25 Punkte</h3>
        <p>Kein Extra-Button mehr. Nach dem Countdown geht’s direkt zurück ins Dashboard.</p>
      </div>
    </section>

    ${
      ig.claimedAt
        ? ""
        : `
          <script>
            const openBtn = document.getElementById("openInstagram");
            const countdownEl = document.getElementById("countdownValue");
            const statusEl = document.getElementById("taskStatus");
            let running = false;

            async function finishInstagramTask() {
              statusEl.textContent = "Punkte werden verbucht...";

              try {
                const res = await fetch("/tasks/instagram/complete", {
                  method: "POST",
                  headers: { "Content-Type": "application/x-www-form-urlencoded" },
                  body: ""
                });

                if (res.redirected) {
                  window.location.href = res.url;
                  return;
                }

                window.location.href = "/account?success=Instagram+Aktion+abgeschlossen";
              } catch (error) {
                console.error(error);
                statusEl.textContent = "Fehler. Bitte erneut versuchen.";
                running = false;
                if (openBtn) openBtn.disabled = false;
              }
            }

            openBtn?.addEventListener("click", async () => {
              if (running) return;
              running = true;
              openBtn.disabled = true;

              window.open(${JSON.stringify(INSTAGRAM_URL)}, "_blank", "noopener,noreferrer");

              try {
                await fetch("/tasks/instagram/opened", {
                  method: "POST",
                  headers: { "Content-Type": "application/x-www-form-urlencoded" },
                  body: ""
                });
              } catch (error) {
                console.error(error);
              }

              let countdown = 5;
              countdownEl.textContent = String(countdown);
              statusEl.textContent = "Läuft...";

              const timer = setInterval(async () => {
                countdown -= 1;

                if (countdown > 0) {
                  countdownEl.textContent = String(countdown);
                  return;
                }

                clearInterval(timer);
                countdownEl.textContent = "✓";
                await finishInstagramTask();
              }, 1000);
            });
          </script>
        `
    }
  `;

  res.send(page({
    title: "Instagram Aktion",
    user,
    body,
    description: "Schnell erledigt, automatisch gutgeschrieben.",
    head,
    pageClass: "instagram-task-page"
  }));
});

app.post("/tasks/instagram/opened", authRequired, async (req, res) => {
  const task = await getTaskState(req.user.id, "instagram");

  await prisma.taskState.update({
    where: { id: task.id },
    data: {
      clickedAt: task.clickedAt || nowDate(),
      status: "opened"
    }
  });

  res.json({ ok: true });
});

app.post("/tasks/instagram/complete", authRequired, async (req, res) => {
  const user = req.user;
  const task = await getTaskState(user.id, "instagram");

  if (!task.clickedAt) {
    return res.redirect("/instagram-task?error=Bitte+erst+Instagram+öffnen");
  }

  if (task.claimedAt) {
    return res.redirect("/account?error=Instagram+bereits+abgeschlossen");
  }

  const secondsSinceOpen = (Date.now() - new Date(task.clickedAt).getTime()) / 1000;
  if (secondsSinceOpen < 5) {
    return res.redirect("/instagram-task?error=Bitte+warte+kurz+bevor+du+abschließt");
  }

  await prisma.$transaction(async tx => {
    await tx.taskState.update({
      where: { id: task.id },
      data: {
        claimedAt: nowDate(),
        status: "done"
      }
    });

    await addEvent(user.id, "instagram", 25, 0, "Instagram Aktion abgeschlossen", {}, tx);
  });

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
  const pin = String(req.body.pin || "").trim();
  const payload = String(req.body.payload || "").trim();

  if (!assertStaffPin(pin)) return res.status(400).json({ ok: false, error: "PIN falsch" });
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
  const pin = String(req.body.pin || "").trim();
  const payload = String(req.body.payload || "").trim();
  const cfg = await ensureScannerConfig();

  if (!assertStaffPin(pin)) return res.status(400).json({ ok: false, error: "PIN falsch" });
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
  const pin = String(req.body.pin || "").trim();
  const payload = String(req.body.payload || "").trim();

  if (!assertStaffPin(pin)) {
    return res.status(400).json({ ok: false, error: "PIN falsch" });
  }

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
  const pin = String(req.body.pin || "").trim();
  const voucherId = String(req.body.voucherId || "").trim();

  if (!assertStaffPin(pin)) {
    return res.status(400).json({ ok: false, error: "PIN falsch" });
  }

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

app.get("/admin", adminRequired, async (req, res) => {
  const [
    scannerConfig,
    userCount,
    pendingCount,
    openVoucherCount,
    users,
    pendingSubmissions,
    customTasks,
    recentCodes
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
    prisma.customTask.findMany({ orderBy: { createdAt: "desc" } }),
    prisma.adminCode.findMany({ orderBy: { createdAt: "desc" }, take: 10 })
  ]);

  const body = `
    ${renderFlash(req)}

    <section class="summary-grid">
      ${statCard(userCount, "Kunden")}
      ${statCard(pendingCount, "Offene Prüfungen")}
      ${statCard(openVoucherCount, "Voucher offen")}
    </section>

    <section class="card">
      <div class="section-head">
        <h3>Admin Zentrale</h3>
        <p>Eine Seite für Check-ins, individuelle Buchungen, Gutschein-Einlösungen und den Managing Hub.</p>
      </div>

      <label>Staff PIN<input id="adminSharedPin" type="password" placeholder="PIN" autocomplete="one-time-code" /></label>

      <div class="button-row" id="adminSectionSwitch">
        <button class="btn btn-primary adminTabBtn" type="button" data-target="panel-checkin">1. Check-In Scanner</button>
        <button class="btn btn-ghost adminTabBtn" type="button" data-target="panel-custom">2. Individueller Scanner</button>
        <button class="btn btn-ghost adminTabBtn" type="button" data-target="panel-voucher">3. Gutschein Scanner</button>
        <button class="btn btn-ghost adminTabBtn" type="button" data-target="panel-managing">4. Managing Hub</button>
      </div>
    </section>

    <section class="card admin-panel" id="panel-checkin">
      <div class="section-head">
        <h3>Check-In Scanner</h3>
        <p>Daily Check-in mit festem Ablauf: +10 Punkte, nur 1x pro Tag.</p>
      </div>

      <div class="grid two">
        <div class="card">
          <div class="button-row">
            <button class="btn btn-primary" id="startCheckinScan">Scanner starten</button>
            <button class="btn btn-secondary" id="stopCheckinScan" disabled>Stoppen</button>
          </div>
          <div id="checkinScanStatus" class="status-line">Bereit.</div>
          <div class="task-block">
            <strong>Fixe Buchung</strong>
            <p class="muted-text">${escapeHtml(scannerConfigSummary(DAILY_CHECKIN_CONFIG))}</p>
          </div>
        </div>

        <div class="card">
          <h3>Kamera</h3>
          <div id="readerCheckin" class="reader"></div>
        </div>
      </div>

      <div class="card">
        <h3>Letzte Check-ins</h3>
        <div id="checkinLog" class="event-list"></div>
      </div>
    </section>

    <section class="card admin-panel" id="panel-custom" hidden>
      <div class="section-head">
        <h3>Individueller Scanner</h3>
        <p>Flexible Buchung für Sonderfälle, Bestellungen oder Aktionen.</p>
      </div>

      <section class="grid two">
        <form class="card form-card" method="post" action="/admin/scanner-config">
          <h3>Scanner konfigurieren</h3>
          <label>Label<input name="label" required value="${escapeHtml(scannerConfig.label)}" /></label>
          <label>Punkte<input name="addPoints" type="number" value="${Number(scannerConfig.addPoints || 0)}" /></label>
          <label>Pizzen<input name="addPizzas" type="number" value="${Number(scannerConfig.addPizzas || 0)}" /></label>
          <label class="check-row"><input type="checkbox" name="oncePerDay" ${scannerConfig.oncePerDay ? "checked" : ""} /> Nur 1x pro Tag</label>
          <label class="check-row"><input type="checkbox" name="active" ${scannerConfig.active ? "checked" : ""} /> Scanner aktiv</label>
          <button class="btn btn-primary" type="submit">Speichern</button>
        </form>

        <div class="card form-card">
          <h3>Scanner benutzen</h3>
          <p>${escapeHtml(scannerConfigSummary(scannerConfig))}</p>
          <div class="button-row">
            <button class="btn btn-primary" type="button" id="startCustomScan">Scanner starten</button>
            <button class="btn btn-secondary" type="button" id="stopCustomScan" disabled>Stoppen</button>
          </div>
          <div id="customScanStatus" class="status-line">Bereit.</div>
          <div id="readerCustom" class="reader"></div>
        </div>
      </section>

      <section class="grid two">
        <form class="card form-card" method="post" action="/admin/create-code">
          <h3>Einmalcode erstellen</h3>
          <label>Label<input name="label" required placeholder="2 bestellte Pizzen / BBQ Test / +25 Punkte" /></label>
          <label>Punkte<input name="addPoints" type="number" value="0" /></label>
          <label>Pizzen<input name="addPizzas" type="number" value="0" /></label>
          <button class="btn btn-secondary" type="submit">Code erzeugen</button>
        </form>

        <div class="card">
          <h3>Letzte Scans</h3>
          <div id="customScanLog" class="event-list"></div>
        </div>
      </section>
    </section>

    <section class="card admin-panel" id="panel-voucher" hidden>
      <div class="section-head">
        <h3>Gutschein Scanner</h3>
        <p>Karte scannen, offenen Gutschein auswählen und direkt verbuchen.</p>
      </div>

      <section class="grid two">
        <div class="card">
          <div class="button-row">
            <button class="btn btn-primary" id="startVoucherScan">Scanner starten</button>
            <button class="btn btn-secondary" id="stopVoucherScan" disabled>Stoppen</button>
          </div>
          <div id="voucherScanStatus" class="status-line">Bereit.</div>
        </div>

        <div class="card">
          <h3>Kamera</h3>
          <div id="readerVoucher" class="reader"></div>
        </div>
      </section>

      <section class="card">
        <h3>Offene Voucher</h3>
        <div id="voucherSelection"><p class="muted-text">Noch kein Kunde gescannt.</p></div>
      </section>

      <section class="card">
        <h3>Einlösungen</h3>
        <div id="voucherLog" class="event-list"></div>
      </section>
    </section>

    <section class="card admin-panel" id="panel-managing" hidden>
      <div class="section-head">
        <h3>Managing Hub</h3>
        <p>Prüfungen, Aktionen, Codes und Kunden in einer Übersicht.</p>
      </div>

      <section class="grid two">
        <form class="card form-card" method="post" action="/admin/custom-tasks">
          <h3>Neue Aktion erstellen</h3>
          <label>Titel<input name="title" required placeholder="Like + Kommentar auf Instagram Post" /></label>
          <label>Beschreibung<input name="description" required placeholder="Kurze klare Erklärung" /></label>
          <label>Ziel-Link<input name="targetUrl" placeholder="https://instagram.com/... oder https://tiktok.com/..." /></label>
          <label>Punkte<input name="points" type="number" value="20" required /></label>
          <label class="check-row"><input type="checkbox" name="active" checked /> Aktion aktiv</label>
          <button class="btn btn-primary" type="submit">Aktion erstellen</button>
        </form>

        <div class="card">
          <h3>Aktionen</h3>
          ${
            customTasks.length
              ? `<div class="event-list">${customTasks.map(task => `
                  <div class="event-row">
                    <div>
                      <strong>${escapeHtml(task.title)}</strong>
                      <small>${escapeHtml(task.description)}</small>
                      ${task.targetUrl ? `<div><a href="${escapeHtml(task.targetUrl)}" target="_blank" rel="noreferrer">${escapeHtml(task.targetUrl)}</a></div>` : ""}
                    </div>
                    <div class="button-stack">
                      <span class="chip">${task.points} Pkt</span>
                      <form method="post" action="/admin/custom-tasks/${task.id}/toggle">
                        <button class="btn btn-ghost" type="submit">${task.active ? "Deaktivieren" : "Aktivieren"}</button>
                      </form>
                    </div>
                  </div>
                `).join("")}</div>`
              : `<p class="muted-text">Noch keine Aktionen erstellt.</p>`
          }
        </div>
      </section>

      <section class="card">
        <h3>Offene Prüfungen</h3>
        ${
          pendingSubmissions.length
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
            : `<p class="muted-text">Keine offenen Prüfungen.</p>`
        }
      </section>

      <section class="grid two">
        <div class="card">
          <h3>Einmalcodes</h3>
          ${
            recentCodes.length
              ? `<div class="event-list">${recentCodes.map(c => `
                  <div class="event-row">
                    <div>
                      <strong>${escapeHtml(c.code)}</strong>
                      <small>${escapeHtml(c.label)}</small>
                    </div>
                    <div class="event-side">${c.usedAt ? "eingelöst" : "offen"}</div>
                  </div>
                `).join("")}</div>`
              : `<p class="muted-text">Noch keine Codes.</p>`
          }
        </div>

        <div class="card">
          <h3>Kunden</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>Name</th><th>E-Mail</th><th>Punkte</th><th>Pizzen</th><th>Voucher</th></tr>
              </thead>
              <tbody>
                ${users.map(u => `
                  <tr>
                    <td>${escapeHtml(u.name)}</td>
                    <td>${escapeHtml(u.email)}</td>
                    <td>${u.points}</td>
                    <td>${u.pizzaCount}</td>
                    <td>–</td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </section>

    <script src="https://unpkg.com/html5-qrcode"></script>
    <script>
      const pinInput = document.getElementById("adminSharedPin");
      const panelButtons = Array.from(document.querySelectorAll(".adminTabBtn"));
      const panels = Array.from(document.querySelectorAll(".admin-panel"));
      const scannerState = {};
      let selectedVouchers = [];
      let selectedVoucherUser = "";

      function getPin() {
        return pinInput?.value.trim() || "";
      }

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

          const pin = getPin();
          if (!pin) {
            statusEl.textContent = "Bitte zuerst die Staff PIN eingeben.";
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
                form.set("pin", pin);

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
            const pin = getPin();
            const statusEl = document.getElementById("voucherScanStatus");
            if (!pin) {
              statusEl.textContent = "Bitte zuerst die Staff PIN eingeben.";
              return;
            }

            const form = new URLSearchParams();
            form.set("voucherId", btn.getAttribute("data-voucher-id"));
            form.set("pin", pin);

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

          const pin = getPin();
          if (!pin) {
            statusEl.textContent = "Bitte zuerst die Staff PIN eingeben.";
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
                form.set("pin", pin);

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
    description: "Übersicht für Check-ins, Scanner, Prüfungen und Kunden."
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
  const code = crypto.randomBytes(4).toString("hex").toUpperCase();

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
    await ensureScannerConfig();
  } catch (error) {
    console.error("Scanner config bootstrap failed", error);
  }

  if (!DEV_AUTO_VERIFY) {
    await verifyMailerConnection();
  }

  console.log(`${BRAND_NAME} läuft auf ${APP_URL}`);
});