# SecureHire Assessment Monitor (Chrome MV3)

Consent-based monitoring for SecureHire assessments. It records **event types and timestamps only** during an explicitly started session on an allowlisted SecureHire page, and sends them to the SecureHire API with a short-lived, session-scoped token.

## Install (Load unpacked)
1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → choose this `extension/` folder.
3. Extension ID (fixed by the `key` in `manifest.json`): **`mlfnbgkkkndpcbmleppgablahalkeedn`**.
4. Open the SecureHire assessment page — it detects the extension automatically (or use `http://localhost:5173/extension-test.html`).

## How it connects
```
Web app (allowlisted origin)                     Extension (background.js)                API
  PING ───────────────────────────────────────▶  { ok, version, active }
  POST /api/assessment/sessions (after consent) ───────────────────────────────────────▶ { sessionId, sessionToken }
  START_SESSION { sessionId, sessionToken, apiBaseUrl, consentGiven:true } ─▶ start monitoring that tab
                                                   content.js events ─▶ queue ─▶ POST /api/events (Bearer sessionToken)
  GET_STATUS ─────────────────────────────────▶  { active, sessionId, counts, backend, queued }
  END_SESSION ────────────────────────────────▶  SESSION_END, flush, stop
```
Requests are accepted only from origins in `externally_connectable`; `apiBaseUrl` must also be allowlisted. Events carry an `idempotencyKey`; failed sends stay queued in `chrome.storage.local` and retry with `chrome.alarms` (30 s). A 401/410 from the API clears the queue.

## Desktop agent bridge (v1.1)
When the page passes an `agentToken` in `START_SESSION`, the extension forwards `{sessionId, agentToken, apiBaseUrl}` to the SecureHire desktop agent at `http://127.0.0.1:47615/session/start`. The agent verifies the token with SecureHire and returns a control token, which is kept in `chrome.storage.session` (memory only). The extension then:
* forwards tab/focus/fullscreen event types to the agent for local correlation (never copy/paste or content),
* polls agent status every 30 s and when the page or popup asks, and shows it in the popup (*Desktop agent* card with monitor states and any review alerts),
* re-pairs automatically if the agent or service worker restarts, and ends agent monitoring on `END_SESSION`.
If the agent is not running, the assessment is not blocked (unless the employer requires it); the popup and page say so. `AGENT_HEALTH` lets the page check whether the agent is running.

## Events recorded
`SESSION_START/END`, `TAB_HIDDEN/VISIBLE`, `TAB_SWITCH`, `NEW_TAB_OPENED`, `WINDOW_BLUR/FOCUS`, `FULLSCREEN_ENTER/EXIT`, `COPY_ATTEMPT`, `CUT_ATTEMPT`, `PASTE_ATTEMPT`, `CONTEXT_MENU`, `DEVTOOLS_SHORTCUT`, `PRINT_ATTEMPT`, `SESSION_INTERRUPTED`.
Never collected: clipboard contents, keystrokes, form values, page text, or URLs of other tabs. The server additionally strips any `clipboard`/`text` fields.

## Permissions — and why
| Permission | Purpose |
|---|---|
| `storage` | Session state + offline event queue (survives service-worker suspension) |
| `alarms` | Retry delivery of queued events |
| `host_permissions` (localhost:5173/4000 only) | Send events to the SecureHire API; inject the content script on SecureHire pages only |
| `host_permissions` `http://127.0.0.1:47615/*` | Talk to the local desktop agent (loopback only, no content script) |
No `tabs`, `management`, `webRequest`, `<all_urls>` or remote code. `tabs.onCreated/onActivated` are used without URL access.

## Popup
Status (Idle / Monitoring / Local test), session ID, start time, backend state, queued events, and counts for tab changes, focus losses, fullscreen exits and copy/paste attempts. **Local test session** counts events on an allowlisted page without sending anything.

## Honest limits
This is a monitoring and deterrence layer for **one Chrome profile**. It cannot block every website, detect or disable every other extension, see other applications or browsers, or stop a second device or a person off-camera. Events are context for a human reviewer — the API raises *review items*, never cheating verdicts. (Page-level copy/paste/right-click blocking is done by the assessment page itself.)

## Production
Add your deployed origin to `host_permissions`, `content_scripts[0].matches` and `externally_connectable.matches`, then reload the extension. For distribution, publish through the Chrome Web Store (the `key` field can be removed; set `VITE_EXTENSION_ID` in the web app to the store ID).

## Manual test steps
1. Load unpacked; open the popup — status **Idle**.
2. As a candidate at the Assessment stage, click **Begin** → "Extension connected" appears.
3. Agree to consent → pre-test checks → **Start assessment**. Popup shows **Monitoring** and the session ID.
4. Switch tabs, open a new tab, press Esc (fullscreen exit), try paste. Counts rise in the popup and the in-page widget; the recruiter's **Live monitoring** page shows each event live; three focus events within 2 min raise a *review item*.
5. Submit — popup returns to **Idle**; queued events flush. Turn Wi-Fi off mid-test to see `offline — retrying`, then back on to see the queue drain.
