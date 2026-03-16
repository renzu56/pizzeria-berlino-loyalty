# La Piazza Club

Handfestes Free-MVP für:
- Kundenkonten mit E-Mail-Bestätigung
- Apple Wallet Pass via WalletWallet
- stabiler Wallet-QR pro Kunde
- Staff-Scanner mit Kamera
- Admin-Konfiguration: Was macht der Scanner gerade?
- Daily Check-in, X Pizzas, X Points
- Instagram Follow / Google Review Click-to-Claim
- TikTok-Link-Submission + Admin-Freigabe
- Pizza Counter
- Rewards:
  - 15 Punkte → 10% Rabatt
  - 50 Punkte → kostenloses Getränk
  - 175 Punkte → 50% Rabatt
  - 300 Punkte → kostenlose Pizza
- automatisch freie Pizza bei jedem 10er-Pizza-Meilenstein

## Start

```bash
cp .env.example .env
npm install
npm run dev
```

Dann öffnen:
- `http://localhost:3000`

## Erster Admin
1. Trage deine E-Mail in `.env` bei `ADMIN_EMAILS=` ein.
2. Registriere dich mit genau dieser E-Mail.
3. Bestätige die Mail:
   - ohne SMTP: `http://localhost:3000/dev/mailbox`
   - mit SMTP: normal im Postfach

## Wichtige Seiten
- `/login`
- `/register`
- `/account`
- `/wallet`
- `/staff`
- `/admin`
- `/dev/mailbox` (nur Development)

## WalletWallet
1. Kostenlosen API-Key anlegen
2. In `.env` setzen:
   - `WALLETWALLET_API_KEY=...`
3. Im Kundenkonto auf **Apple Wallet Pass erstellen** klicken

## Handy-Scanner testen
Für reine Erreichbarkeit im WLAN:
- `http://DEINE-IP:3000`

Für Kamera-Scanning auf dem Handy im Browser besser über HTTPS-Tunnel:
- z. B. `ngrok http 3000`
- oder Cloudflare Tunnel

## Scanner-Logik
Im Admin legst du die aktuelle Aktion fest:
- Label
- Punkte
- Pizzen
- nur 1x pro Tag?
- aktiv / inaktiv

Dann im Staff-Scanner scannst du die Wallet-QRs nacheinander.
Jeder Scan wendet genau diese Konfiguration auf den gescannten Kunden an.
