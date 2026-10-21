# PROGRESS — verified status

Last verified: 9 Oct 2026, on Node 22.22 + headless Chromium (Playwright) with the unpacked extension loaded and a synthetic fake-camera feed.

## How it was tested
- **API test suite** (`npm test`, 9 suites, all passing): auth & RBAC; Apply (email OTP, mock Aadhaar, Verhoeff, HMAC uniqueness, plaintext never in DB); trust engine lifecycle; identity enrolment, duplicate face search, continuity rule; resume extraction + APAAR mismatch; extension endpoint (token auth, idempotency, clipboard stripping, integrity rule, closed-session rejection); location (consent, neutral denial, contextual jump); offers (signature, QR verify, tamper detection, held-for-review acceptance, PDF report); admin weights validation + retention.
- **Browser E2E** (Chromium + extension): register → email OTP → Aadhaar → camera with MediaPipe (478 landmarks, 52 blendshapes detected) → face-api descriptor → enrolment → resume upload/report → assessment with extension (PING, START_SESSION, events delivered, backend `connected`, face continuity "Identity verified") → submit. Same-face continuity distance 0.06–0.13 (match); different face 0.62 (mismatch → review flag after 2 checks). Two-browser WebRTC interview: camera + screen share received by recruiter, live face continuity 91 %, voice enrolment, completion moved the candidate to Offer. `extension-test.html` flow verified.
- Frontend `tsc --noEmit` + `vite build` clean.

## Feature verification table

| Feature | Status | Notes |
|---|---|---|
| Candidate / recruiter / admin auth, role-based routing | WORKING | bcrypt, httpOnly JWT cookie, server-side RBAC |
| Persistent database, migrations, seed | WORKING | node:sqlite (WAL); `npm run seed` resets demo data |
| Email OTP verification | WORKING (dev delivery) | OTP printed to console / shown in demo mode; SMTP not wired |
| Aadhaar OTP verification | SIMULATED | Mock provider with success/failure/pending/unavailable outcomes; real UIDAI needs an authorized AUA/KUA |
| One Aadhaar ↔ one account (HMAC), duplicate blocked + review flag | WORKING | Plaintext never stored (verified by test) |
| Session/IP observation, IP-change detection | WORKING | Server-side IP, masked; trusted-proxy config |
| Approximate IP geolocation | REQUIRES EXTERNAL API | ip-api.com free tier at runtime; degrades to "unavailable" offline |
| MediaPipe 478-landmark mesh overlay, head pose, lighting, face count | WORKING | Vendored model, runs offline in browser |
| Guided liveness (blink, head turns, re-centre) | WORKING (basic) | Not certified presentation-attack detection; needs a real person (untestable with static video) |
| Face embedding + identity anchor (encrypted) | WORKING | face-api FaceRecognitionNet 128-d |
| ID-photo 1:1 match, 1:N duplicate face search | WORKING | Linear scan (demo scale) |
| DigiLocker documents | SIMULATED | Mock provider (success/mismatch/missing) |
| Resume upload (PDF/DOCX/TXT), parsing, claims | WORKING | Rule/regex extraction (spaCy/LayoutLMv3 not used) |
| Semantic claim comparison (Sentence-Transformers MiniLM) | WORKING | Local ONNX; lexical fallback if disabled |
| APAAR academic records | SIMULATED | Synthetic registry |
| Employment verification | SIMULATED | Synthetic employer confirmations; statuses Verified/Mismatch/Unverifiable |
| Timeline rules, version diff, duplicate-resume detection | WORKING | |
| GitHub public evidence | REQUIRES EXTERNAL API | Best-effort GitHub API lookup |
| LLM narrative summary | REQUIRES EXTERNAL API | Claude API when `ANTHROPIC_API_KEY` set; rule-based summary otherwise |
| Chrome MV3 extension (detect, consent-gated session, monitoring, queue/retry, popup) | WORKING | Monitoring only by design; honest limits documented |
| Assessment runner, timer, auto-submit, scoring, page-level copy/paste/right-click blocking | WORKING | Coding question scored by keyword heuristic |
| Continuous face monitoring during assessment/interview | WORKING | Every 10 s; flag after 2 consecutive mismatches |
| Behaviour analytics (fast-correct, uniform timing) | WORKING | Rule-based |
| Desktop security agent: USB connect/disconnect (Windows) | IMPLEMENTED · logic TESTED · Windows API layer NEEDS WINDOWS TEST | SetupAPI + WM_DEVICECHANGE; salted device hash; storage → review, peripherals → info |
| Desktop agent: newly launched apps | WORKING | psutil; tested with a real process launch; name + PID only |
| Desktop agent: potential overlay windows | IMPLEMENTED · rules TESTED · Windows API layer NEEDS WINDOWS TEST | Always-on-top, size, overlap, transparency, capture exclusion; combined signals only |
| Desktop agent: rules engine, correlation, cooldowns | WORKING | Explainable; info / review only; no scores |
| Local FastAPI service (loopback, origin/host checks, control token, limits) | WORKING | 127.0.0.1 binding verified |
| Extension ↔ agent bridge | WORKING (mocked Chrome API tests) | Manual check in desktop Chrome recommended |
| Backend agent endpoints, heartbeats, disconnect detection, recruiter review | WORKING | 7 new API tests + real end-to-end agent→backend test |
| Recruiter Desktop security panel | BUILT (tsc + vite clean) | Not visually inspected in a browser during this change |
| Audio second-speaker detection | NOT IMPLEMENTED | Mic required; VAD/second-speaker model not included |
| Live 1:1 WebRTC interview + mandatory screen share | WORKING | STUN only — production needs TURN |
| GPS Map Camera-style overlay (device GPS, IP fallback, live clock) | WORKING | Reverse geocoding via OpenStreetMap Nominatim at runtime |
| Voice consistency | WORKING (EXPERIMENTAL) | MFCC voiceprint, not a validated speaker model |
| Lip-sync consistency | WORKING (EXPERIMENTAL) | Mouth-opening vs mic-energy correlation; logs an event only |
| Assessment ↔ interview comparison | WORKING | Network, location distance, face distances |
| Trust engine, statuses, if-confirmed projection, history, explainability | WORKING | |
| Real-time recruiter updates (WebSockets) | WORKING | Live alerts bell, overview, live monitor, candidate page |
| Human review (confirm/dismiss with reason), appeals, clarification requests | WORKING | Audit-logged |
| Offers: signed record, QR, public verification, tamper detection, revoke | WORKING | |
| Offer acceptance with fresh face + Aadhaar re-check; held-for-review path | WORKING | |
| Onboarding: documents, mock DigiLocker, day-one face check, approval | WORKING (DigiLocker SIMULATED) | |
| Final verification report (PDF) | WORKING | |
| Admin: weights, stage weights, retention, allowlist, users/roles, audit log | WORKING | |
| Retention job with audit-logged deletion | WORKING | Hourly + on demand |
| PostgreSQL + pgvector | NOT IMPLEMENTED | SQLite chosen for zero-setup demo; documented migration path |
| Docker Compose | NOT IMPLEMENTED | Not needed — `npm run dev` runs everything |

## Known limitations / untested
- Liveness challenges and real-camera lighting variation require a human tester (tested only with a static synthetic video).
- Voice and lip-sync heuristics are experimental and noise-sensitive.
- Seeded demo candidates use random synthetic face vectors (they cannot be matched by a real camera); create a new account to test live face checks.
- Google Fonts load from the internet (falls back to system fonts offline).
- Extension tested in headless Chromium; manual check in desktop Chrome recommended before the demo (steps in `extension/README.md`).
