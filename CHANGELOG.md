# Visible UI Fix

- Reward buttons removed; available reward cards are directly clickable.
- Reward cost text moved below the title and reduced.
- Reward progress bars are classed and constrained to the card width.
- TikTok card is bound to tiktokSubmission and no longer behaves like Review.
- Action descriptions removed, including “Gerade verfügbar”.
- Instagram button made smaller and the explanation text removed.
- Review/TikTok inputs made smaller on mobile.
- node --check server.js passed.

## Direct mobile actions fix

- TikTok action now uses its own TikTok badge and short link field.
- Google action now uses Google badge, not Review.
- Instagram click now completes instantly without waiting for app return/focus.
- Action input fields and buttons are compact on desktop and mobile.
- Reward cost text and progress bars are constrained inline and via CSS to prevent overflow.

## TikTok review badge correction

- TikTok task title stays `🎬 TikTok Beitrag`.
- TikTok task badge now shows `Review`, same concept as Google Bewertung.
- Direct Instagram completion and compact input fixes stay unchanged.
