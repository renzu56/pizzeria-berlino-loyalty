/*
  Replace only these parts in your main Express file.
  This patch fixes:
  1) logo overflowing on mobile
  2) topbar not behaving like a normal element
  3) register form stretching down to the footer
  4) footer staying at the real page bottom
*/

function brandLogoMarkup() {
  if (!fs.existsSync(brandLogoPath)) return "";
  return `<img src="/brand-logo" alt="${escapeHtml(BRAND_NAME)} Logo" class="brand-logo-img" />`;
}

function page({ title, user, body, description = "", head = "", pageClass = "" }) {
  const sharedHead = `
    <style>
      .topbar {
        position: static !important;
        top: auto !important;
        z-index: auto !important;
        display:flex;
        align-items:center;
        justify-content:space-between;
        gap:18px;
      }

      .brand.brand-expanded {
        display:flex;
        align-items:center;
        gap:18px;
        min-width:0;
        flex:1 1 auto;
      }

      .brand.brand-expanded .brand-icon {
        width:96px;
        height:96px;
        padding:8px;
        overflow:hidden;
        border-radius:22px;
        background:#fff7f1;
        border:1px solid rgba(191,90,52,.12);
        box-shadow:0 10px 24px rgba(56,31,13,.08);
        display:grid;
        place-items:center;
        flex:0 0 auto;
      }

      .brand.brand-expanded .brand-title {
        font-size:clamp(24px,3vw,34px);
        line-height:1.02;
      }

      .brand.brand-expanded .brand-subtitle {
        margin-top:6px;
        font-size:13px;
      }

      .footer-brand-link,
      .page-footer a {
        color:#bf5a34;
        font-weight:700;
        text-decoration:none;
      }

      @media (max-width: 760px) {
        .topbar {
          flex-direction:row;
          align-items:center;
        }

        .brand.brand-expanded .brand-icon {
          width:64px;
          height:64px;
          padding:6px;
          border-radius:16px;
        }
      }

      @media (max-width: 520px) {
        .topbar {
          flex-direction:column;
          align-items:flex-start;
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

app.get("/register", async (req, res) => {
  const user = await getCurrentUser(req);
  if (user) return res.redirect("/account");

  const pendingEmail = String(req.query.email || "").trim().toLowerCase();
  const showVerificationState = !!pendingEmail && !!req.query.success;

  const registerHead = `
    <style>
      .register-page .page {
        display:block;
        flex:0 0 auto;
      }

      .register-stage {
        display:flex;
        justify-content:center;
        align-items:flex-start;
      }

      .register-card-center {
        width:min(100%, 620px);
        max-width:620px;
        flex:0 0 auto;
        height:auto;
        min-height:0;
        align-self:flex-start;
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
          <h3>Bestätigungslink gesendet</h3>
          <div class="verify-email-chip">${escapeHtml(pendingEmail)}</div>
          <p class="muted-text" style="margin:14px 0 0">Bitte bestätige deine E-Mail-Adresse und logge dich danach ein.</p>

          <div class="button-row" style="margin-top:18px">
            <a class="btn btn-secondary" href="/login">Zum Login</a>
          </div>

          <div class="resend-inline-helper" id="resendHint" hidden>
            Mail nicht angekommen?
            <button type="button" id="toggleResendPanel">Dann hier nochmal senden</button>
          </div>

          <form class="mini-resend-form" id="resendPanel" method="post" action="/resend-verification" hidden>
            <input type="hidden" name="email" value="${escapeHtml(pendingEmail)}" />
            <span>Bestätigungslink erneut senden</span>
            <button type="submit">Jetzt senden</button>
          </form>
        </div>
      </section>

      <script>
        const resendHint = document.getElementById("resendHint");
        const resendPanel = document.getElementById("resendPanel");
        const toggleResendPanel = document.getElementById("toggleResendPanel");

        if (resendHint) {
          window.setTimeout(() => {
            resendHint.hidden = false;
          }, 4000);
        }

        toggleResendPanel?.addEventListener("click", () => {
          resendPanel.hidden = !resendPanel.hidden;
        });
      </script>
    `
    : `
      ${renderFlash(req)}
      <section class="register-stage">
        <form class="card form-card register-card-center" method="post" action="/register">
          <h3>Pizza-Berlino-Konto erstellen</h3>
          <label>Name<input name="name" required placeholder="Valentina Rossi" /></label>
          <label>E-Mail<input type="email" name="email" required placeholder="kunde@beispiel.de" /></label>
          <label>Passwort<input type="password" name="password" required minlength="6" placeholder="Mind. 6 Zeichen" autocomplete="new-password" /></label>
          <button class="btn btn-primary" type="submit">Mitglied werden</button>
        </form>
      </section>
    `;

  res.send(page({
    title: "Mitglied werden",
    user,
    body,
    description: "Registrieren, bestätigen und direkt loslegen.",
    head: registerHead,
    pageClass: "register-page"
  }));
});
