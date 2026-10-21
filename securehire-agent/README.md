# SecureHire Desktop Security Agent (Windows)

A transparent, assessment-scoped Windows agent. During an authorised SecureHire assessment it records:

| What | How | What is sent |
|---|---|---|
| USB connect / disconnect | `WM_DEVICECHANGE` notifications + SetupAPI snapshot diff | category (storage, input, camera…), VID/PID, Windows class/service, **salted per-session hash** of the device instance ID |
| Newly launched apps | process list poll (psutil), current user only | executable name, PID |
| Potential overlay windows | `EnumWindows` + window styles, display affinity, DWM cloaking | process name, size/position, always-on-top, layered/alpha, click-through, capture-excluded, overlap % with the assessment window |

It **never** reads files or drive contents, keystrokes, passwords, clipboard, command lines, window titles/contents, or the screen. It never terminates, suspends, or modifies apps or devices. It shows a visible status window the whole time it runs.

Every event is an **observation** (`info` or `review`). Nothing is a verdict: only a human reviewer in SecureHire can mark something as a confirmed policy violation, with a written reason.

## How it fits together

```
SecureHire page ──START_SESSION {agentToken}──▶ Chrome extension ──POST /session/start──▶ Agent (127.0.0.1:47615)
                                                                                         │ verifies token with
                                                                                         ▼ GET /api/agent/session
                                         Recruiter dashboard ◀── WebSocket ◀── SecureHire API ◀── POST /api/agent/events
                                                                                              ◀── POST /api/agent/heartbeat (15 s)
```

* The **agent token** is issued per assessment session, separate from the extension's token, and accepted only by `/api/agent/*`.
* The agent reports only to API addresses on its allowlist (`allowed_api_base_urls`), so it cannot be redirected elsewhere.

## Run it

Requirements: Windows 10/11, Python 3.10+ (python.org installer, which includes Tkinter). **No administrator rights needed.**

```bat
cd securehire-agent
start-agent.bat              :: creates .venv, installs requirements, opens the status window
:: or
python -m pip install -r requirements.txt
python -m agent.main         :: --headless for console only, --config path\to\config.json, --port N
```

Then, in Chrome with the SecureHire extension v1.1 loaded, start an assessment. The pre-check shows "Desktop security agent: Running", and the agent window switches to "Monitoring this assessment".

### Build an .exe for distribution
```powershell
.\packaging\build_windows.ps1      # runs tests, then PyInstaller → dist\securehire-agent.exe
```
Sign the executable with your organisation's code-signing certificate before distributing it.

### Configuration
Copy `config.example.json` to `%PROGRAMDATA%\SecureHireAgent\config.json` (or pass `--config`). Unknown keys are rejected. Key settings:
* `allowed_api_base_urls`: add your production SecureHire URL (HTTPS required except for localhost).
* `allowlisted_processes`: accessibility tools and approved software, never treated as suspicious.
* `usb_storage_review`: whether USB storage connections are marked "needs review" (default true).
* Window rule thresholds: `small_window_max_screen_percent`, `overlap_min_percent`, `transparent_alpha_max`.
* Correlation: `correlation_window_seconds`, `correlation_min_categories`, `correlation_cooldown_seconds`.

Logs: `%LOCALAPPDATA%\SecureHireAgent\logs\agent.log` (rotating, 3 × 1 MB, tokens redacted).

### Uninstall
Close the agent window, then delete the agent folder (or `securehire-agent.exe`) and `%LOCALAPPDATA%\SecureHireAgent`. Nothing is installed as a service, scheduled task or startup item.

## Rules (explainable, configurable)

| Rule | Priority | Fires when |
|---|---|---|
| `usb.peripheral_connected` | info | keyboard, mouse, camera, audio or other non-storage device connects |
| `usb.storage_connected` | review (configurable) | storage or portable device (phone in file mode) connects |
| `process.new_application` | info | a non-system app that was not running at the start launches (each name once) |
| `window.allowlisted` | info | always-on-top window from an allowlisted tool |
| `window.overlay_candidate` | review | **all of:** launched during the assessment, always-on-top, small (≤35 % of screen), ≥20 % over the assessment window |
| `window.capture_excluded` | review | window hidden from screen capture **and** always-on-top or over the assessment |
| `window.transparent_overlay` | review | semi-transparent/click-through **and** always-on-top **and** over the assessment |
| `window.topmost_new` / `topmost_preexisting` | info | other always-on-top windows (context only) |
| `correlation.multi_indicator` | review | ≥2 different indicator types (USB storage, unknown app, review window) within 120 s, with a 5-minute cooldown |
| `agent.agent_stopped` | review | the candidate closed the agent during an assessment |
| `AGENT_DISCONNECTED` (server) | review | no heartbeat for 45 s during an active session |

There are no scores or probabilities. "Review" means "a person should look", nothing more.

## Local service security
Bound to `127.0.0.1` only. Host header checked (blocks DNS rebinding). Only the extension's origin is allowed, and POSTs must carry it. `/session/start` needs a SecureHire-verified agent token and returns a per-session control token required by all other endpoints. Bodies are limited to 16 KB, strictly validated, and rate-limited. There are no file, process, shell or settings endpoints. Plain HTTP on loopback is used, since Chrome allows extensions to call `http://127.0.0.1` with a matching host permission; no certificate is needed.

## Tests
```bash
python -m pytest -q        # 55 tests; Windows APIs replaced by fakes with the same interface
```
`test_integration_backend.py` starts the real Node backend and runs the real agent session, rules engine and delivery client against it (skipped if Node or `server/node_modules` is missing).

**Requires a real Windows machine (not verified by the automated tests):** `win32_usb.py` (SetupAPI enumeration and device notifications), `win32_windows.py` (window enumeration, styles, display affinity, DPI handling), the Tkinter status window, and the PyInstaller build. Manual check:
1. Start the agent, then start an assessment. The window shows *Monitoring*, and the recruiter's Live monitoring shows *Agent connected*.
2. Plug in a USB mouse: one informational event. Plug in a USB stick: one *needs review* event. Unplug and re-plug: disconnect and connect events.
3. Launch Notepad: one *app started* event (once per name).
4. Open a small always-on-top window over the browser from a newly started app (e.g. a sticky-note app with "always on top"): one *potential overlay* review event.
5. Turn Wi-Fi off for 1 minute: the window shows *offline, events queued*; the recruiter sees *Agent disconnected*. Back online: queued events arrive, plus *reconnected*.
6. Close the agent mid-assessment: a warning dialog appears, then an *agent stopped* review event.

## Known limitations
* **Not every overlay can be detected.** Overlays drawn inside the browser (extensions, page injections), DirectX/game-overlay hooks drawn into another app's surface, apps that disguise their process name, windows on other virtual desktops (cloaked), a second device, or another person in the room are invisible to metadata-based detection.
* Fully transparent windows using per-pixel alpha (`UpdateLayeredWindow`) report no constant alpha; they are evaluated on their other signals.
* The assessment window is identified by a browser window whose title contains "SecureHire". If the tab is not focused or the title changes, overlap is reported as unknown and window rules stay informational.
* Process names can be renamed; name-based allowlists are a convenience, not a security boundary.
* A determined candidate with admin rights can stop or tamper with any client-side agent. Stops and gaps are reported (heartbeat timeout, agent stopped), not prevented.
