# Pizza Berlino UI Fix

- Reward-Karten sind jetzt selbst klickbar, sobald ein Reward einlösbar ist.
- `ab ... Pkt` ist keine Pill-/Extra-Box mehr, sondern dezente Meta-Info.
- Nicht verfügbare Rewards zeigen keinen Button und kein "Noch nicht verfügbar" mehr.
- Reward-Titel und rechte/linke Karten sind durch feste Kopfhöhe optisch parallelisiert.
- Instagram-Aktion nutzt auf Mobile einen App-Deep-Link und schließt die Punktevergabe beim Zurückkehren ab.
- Unnötiger Instagram-Erklärungstext wurde entfernt.
- Aktionskarten haben Emojis direkt im Titel: 📸 Instagram, ⭐ Google, 🎬 TikTok.
- Aktions-Badges sitzen oben rechts, auch auf Handy.
- Link-Eingaben in Aktionen sind auf Mobile kompakter und haben kürzere Platzhalter.

## Syntax hotfix

- Fixed missing comma in TikTok reward/action card config inside `server.js`.
- Verified with `node --check server.js`.

## Real syntax hotfix verification

- Patched `server.js` directly, not only the changelog.
- TikTok reward/action template now has a valid comma-separated object and includes `submission: tiktokSubmission`.
- Verified with `node --check server.js`.

## Reward/action layout fix

- Reward price text moved below titles and made smaller to prevent overflow.
- Reward progress bars constrained to card width.
- Reward cards aligned to consistent height even with two-line titles.
- Instagram action copy removed and button made smaller.
- TikTok, Google Review and Instagram action labels/badges separated visually.
- Mobile action inputs made more compact.
