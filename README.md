# SecureHire — Candidate Trust & Fraud Intelligence Platform

KERNEL PRIME'26 · SW-03. A continuous trust layer across seven hiring stages — **Apply → Identity → Resume → Assessment → Interview → Offer → Onboarding** — with an explainable trust indicator, human review for every risk flag, and a companion Chrome extension.

> Prototype. Aadhaar, DigiLocker, APAAR and employer confirmations are **simulated providers with synthetic data**, clearly labelled `MOCK` in the UI. Scores are illustrative review indicators, not validated fraud probabilities. Nothing in the system rejects a candidate automatically.

---

## Quick start (local)

Requirements: **Node.js 22.13+** (uses the built-in `node:sqlite`), Chrome 116+.

```bash
npm run install:all      # root + server + web dependencies (~5 min; pulls the AI model packages)
npm run dev              # API on :4000, web on :5173 — first start seeds synthetic demo data
```

Open **http://localhost:5173**.

| Role | Email | Password |
|---|---|---|
| Recruiter | recruiter@securehire.dev | Demo@1234 |
| Admin | admin@securehire.dev | Demo@1234 |
| Candidate (hired, all stages) | priya@demo.securehire.dev | Demo@1234 |
| Other seeded candidates | kiran@ / arjun@ / rahul@ / meera@ / vikram@ `demo.securehire.dev` | Demo@1234 |

Or click **Apply as candidate** to run the live flow with your own camera.

Other commands: `npm test` (API + extension test suites) · `npm run test:agent` (desktop agent, needs Python) · `npm run seed` (reset DB to demo state) · `npm run build` (production web build).

### Desktop security agent (Windows, optional): AI overlay & USB monitoring
Observes USB connections, newly launched apps and potentially suspicious always-on-top / overlay windows **during an assessment only**, and reports explainable observations to the recruiter's **Desktop security** panel (Live monitoring and the candidate page). Nothing is a verdict: only a reviewer can record a policy violation, with a written reason.

```bat
cd securehire-agent
start-agent.bat            :: or: pip install -r requirements.txt && python -m agent.main
```
Reload the extension (v1.1.0 adds the agent bridge), then start an assessment: the pre-check shows the agent, and monitoring starts automatically after consent. To make the agent mandatory, set `monitoring_policy.requireDesktopAgent: true` in admin settings. Full details, rules and limitations: [`securehire-agent/README.md`](securehire-agent/README.md).

### Load the Chrome extension
1. Open `chrome://extensions`, enable **Developer mode**.
2. **Load unpacked** → select the `extension/` folder.
3. The ID is fixed by the manifest key: `mlfnbgkkkndpcbmleppgablahalkeedn` (the web app expects it).
4. Optional smoke test: http://localhost:5173/extension-test.html

Details: [`extension/README.md`](extension/README.md).

### Demo data for the simulated providers
- Aadhaar (checksum-valid, synthetic): shown on the Apply page in demo mode; OTP is always `123456`. The first number belongs to Priya → use it with a new account to see **duplicate identity** blocking.
- APAAR IDs: `100000000001` … `100000000004`, `100000000010`, `100000000011` (Arjun's `…0002` shows the graduation-year mismatch).
- Sample resumes (TXT + PDF): `docs/sample-resumes/`.
- Email OTPs are printed in the server console and shown on screen in demo mode (no SMTP needed).

---

## What's inside

```
securehire/
├── server/        Express API · node:sqlite · WebSockets (live updates + WebRTC signaling) · mock providers · AI resume engine
├── web/           React + TypeScript + Vite + Tailwind · in-browser face models · WebRTC interview room
│   └── public/models/   vendored pretrained weights (MediaPipe + face-api) — works offline
├── extension/     SecureHire Assessment Monitor (Chrome MV3) · tests/ (agent bridge)
├── securehire-agent/  Python Windows desktop security agent + loopback FastAPI service
└── docs/          SPEC.md · PROGRESS.md (feature verification table) · DEMO_SCRIPT.md · sample-resumes/
```

### Pretrained models (integrated, running locally)
| Model | Where | Used for |
|---|---|---|
| **Google MediaPipe Face Landmarker** (`face_landmarker.task`, float16) | Browser (WASM/GPU) | 478-landmark mesh overlay, 52 blendshapes, head pose, guided liveness (blink + head turns), lighting/face-count checks, lip-movement signal |
| **face-api.js** TinyFaceDetector + SSD MobileNet v1 + 68-pt landmarks + **FaceRecognitionNet** (128-d) | Browser (TF.js WebGL) | Face embeddings for the identity anchor, ID-photo 1:1 match, continuity checks every 10 s, 1:N duplicate search (server) |
| **sentence-transformers/all-MiniLM-L6-v2** (ONNX) | Server (onnxruntime-node) | Semantic comparison of degrees, institutions and titles vs verified records |
| MFCC voiceprint (Meyda) | Browser | *Experimental* voice-consistency hint during interviews |

Images and audio never leave the browser — only embeddings/feature vectors are sent and stored (AES-256-GCM encrypted).
Notes: InsightFace was not used because its pretrained weights are non-commercial and require a Python service; face-api's FaceRecognitionNet (dlib-compatible ResNet) is MIT-licensed and runs in-browser.

### Trust engine (summary)
- Every check emits a **signal** with status `verified` (points apply), `pending_review` (**0 points** until a reviewer confirms), `confirmed`, `dismissed` or `contextual` (never affects score — IP/location changes, focus events, GPS denial).
- **Stage score** = 50 + 50 × verified points / stage maximum, minus confirmed risk weights; stages without evidence are *pending*, never failures.
- **Overall** = stage-weighted average over stages with evidence (weights configurable by admin; defaults 10/20/15/20/15/10/10).
- Open high-severity flags set `Review required` and show an **if-confirmed projection** — the number itself never drops automatically.
- History is stored on every change and pushed live over WebSockets.

---

## Deployment

**Single service (simplest):** build the web app and let the API serve it.
```bash
npm run install:all && npm run build
cd server && NODE_ENV=production PUBLIC_WEB_URL=https://your-app.example WEB_ORIGINS=https://your-app.example \
  JWT_SECRET=… AADHAAR_HMAC_KEY=… DATA_ENCRYPTION_KEY=… OFFER_SIGNING_KEY=… TRUST_PROXY=1 DEMO_MODE=true node src/index.js
```
Render / Railway: root `server/`, build `cd .. && npm run install:all && npm run build`, start `node src/index.js`, add a persistent disk for `server/data` (SQLite + encrypted uploads).

**Split:** web on Vercel (`web/`, build `npm run build`, rewrite `/api/*` and `/ws` to the API host) + API on Render/Railway. Set `WEB_ORIGINS` to the Vercel URL.

Production notes:
- **HTTPS is required** for camera, microphone, screen share and geolocation on any non-localhost origin.
- **WebRTC:** signaling runs over the API's `/ws`; public Google STUN is configured. Many corporate/mobile networks need a **TURN server** (e.g. coturn or a managed TURN) — add it to `iceServers` in `server/src/routes/interview.js`.
- **Extension:** add your production origin to `host_permissions`, `content_scripts.matches` and `externally_connectable.matches` in `extension/manifest.json`, and to the admin allowlist.
- SQLite is fine for a demo; for production swap to managed PostgreSQL (+ pgvector for face-embedding search) behind the same `db.js` helpers.
- Replace mock providers in `server/src/providers/` with authorized integrations (AUA/KUA e-KYC partner, DigiLocker Partner API, APAAR via API Setu).

---

## Privacy & fairness controls
Consent per purpose (view/withdraw on *Privacy & consent*) · Aadhaar stored only as HMAC + masked digits · face/voice embeddings and documents encrypted at rest · IPs masked in the UI · configurable retention job with audit-logged deletion · every review decision requires a written reason and is audit-logged · candidates can respond to/appeal every flag · AI-assisted writing, VPNs, IP/location changes and declining optional permissions are never negative signals · facial geometry is never used to judge appearance.

See [`docs/PROGRESS.md`](docs/PROGRESS.md) for the verified feature table and known limitations, and [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) for a 6-minute judge walkthrough.
