"""Agent configuration.

Defaults are safe for local development. Organisations override them with a JSON file
(``--config path`` or ``%PROGRAMDATA%\\SecureHireAgent\\config.json``) — see ``config.example.json``.
No secrets live in configuration: session tokens are issued per assessment by SecureHire
and are only ever held in memory.
"""
from __future__ import annotations

import ipaddress
import json
import os
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Optional

EXTENSION_ID = "mlfnbgkkkndpcbmleppgablahalkeedn"  # fixed by the "key" in extension/manifest.json

# Windows processes that start constantly in the background and say nothing about the assessment.
DEFAULT_TRUSTED_SYSTEM = [
    "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "fontdrvhost.exe", "dwm.exe", "sihost.exe", "taskhostw.exe", "explorer.exe", "ctfmon.exe",
    "runtimebroker.exe", "searchhost.exe", "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe", "textinputhost.exe", "applicationframehost.exe",
    "backgroundtaskhost.exe", "conhost.exe", "dllhost.exe", "wmiprvse.exe", "audiodg.exe", "smartscreen.exe",
    "securityhealthsystray.exe", "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe",
    "wudfhost.exe", "taskmgr.exe", "consent.exe", "useroobebroker.exe", "lockapp.exe", "systemsettings.exe",
    "systemsettingsbroker.exe", "widgets.exe", "widgetservice.exe", "crashpad_handler.exe", "werfault.exe",
    "compattelrunner.exe", "musnotification.exe", "tiworker.exe", "trustedinstaller.exe", "sppsvc.exe",
    "dashost.exe", "rundll32.exe", "msedgewebview2.exe", "identity_helper.exe", "gamebarpresencewriter.exe",
]

# Legitimate tools that must never be treated as suspicious (accessibility, input, approved software).
DEFAULT_ALLOWLIST = [
    # Screen readers / magnifiers / accessibility
    "narrator.exe", "nvda.exe", "nvda_slave.exe", "jfw.exe", "zt.exe", "magnify.exe", "osk.exe", "tabtip.exe",
    "dragon.exe", "natspeak.exe", "zoomtext.exe", "fusion.exe", "windowsspeechrecognition.exe", "voiceaccess.exe",
    # Input utilities
    "powertoys.exe", "powertoys.keyboardmanagerengine.exe", "autohotkey.exe", "logioptionsplus_agent.exe",
    # The SecureHire agent itself
    "securehire-agent.exe",
]

DEFAULT_IGNORED_WINDOW_CLASSES = [
    "Shell_TrayWnd", "Shell_SecondaryTrayWnd", "Progman", "WorkerW", "tooltips_class32", "#32768", "NotifyIconOverflowWindow",
    "Windows.UI.Core.CoreWindow", "Xaml_WindowedPopupClass", "TopLevelWindowForOverflowXamlIsland", "MSCTFIME UI", "IME",
    "ForegroundStaging", "MultitaskingViewFrame", "XamlExplorerHostIslandWindow", "SysShadow", "Chrome_WidgetWin_2",
]


@dataclass
class AgentConfig:
    # Local service (loopback only)
    local_host: str = "127.0.0.1"
    local_port: int = 47615
    allowed_extension_origins: list[str] = field(default_factory=lambda: [f"chrome-extension://{EXTENSION_ID}"])
    # SecureHire API endpoints the agent is allowed to report to (prevents redirecting events elsewhere)
    allowed_api_base_urls: list[str] = field(default_factory=lambda: [
        "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4000", "http://127.0.0.1:4000",
    ])
    api_timeout_seconds: float = 10.0

    # Intervals
    heartbeat_seconds: float = 15.0
    process_poll_seconds: float = 2.0
    window_poll_seconds: float = 1.5
    usb_reconcile_seconds: float = 5.0

    # USB
    usb_monitor_enabled: bool = True
    usb_report_peripherals: bool = True          # keyboards, mice, webcams… (always informational)
    usb_storage_review: bool = True              # storage / portable devices → "needs review"

    # Processes
    process_monitor_enabled: bool = True
    process_report_once_per_name: bool = True
    trusted_system_processes: list[str] = field(default_factory=lambda: list(DEFAULT_TRUSTED_SYSTEM))
    allowlisted_processes: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWLIST))

    # Windows
    window_monitor_enabled: bool = True
    assessment_title_marker: str = "SecureHire"
    browser_process_names: list[str] = field(default_factory=lambda: ["chrome.exe", "msedge.exe"])
    min_window_width: int = 80
    min_window_height: int = 40
    small_window_max_screen_percent: float = 35.0
    overlap_min_percent: float = 20.0
    transparent_alpha_max: int = 230
    window_stable_polls: int = 2
    ignored_window_classes: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORED_WINDOW_CLASSES))

    # Rules engine
    dedupe_cooldown_seconds: float = 30.0
    correlation_window_seconds: float = 120.0
    correlation_min_categories: int = 2
    correlation_cooldown_seconds: float = 300.0

    # Delivery
    queue_max_events: int = 1000
    batch_size: int = 25
    retry_base_seconds: float = 2.0
    retry_max_seconds: float = 60.0

    # Logs & UI
    log_dir: Optional[str] = None
    log_max_bytes: int = 1_000_000
    log_backups: int = 3
    recent_events_kept: int = 100

    def validate(self) -> "AgentConfig":
        try:
            if not ipaddress.ip_address(self.local_host).is_loopback:
                raise ValueError
        except ValueError:
            raise ValueError("local_host must be a loopback address (127.0.0.1 or ::1); the agent never listens on the network.")
        if not (1024 <= self.local_port <= 65535):
            raise ValueError("local_port must be between 1024 and 65535.")
        for o in self.allowed_extension_origins:
            if not o.startswith("chrome-extension://") or o.endswith("/"):
                raise ValueError(f"Invalid extension origin: {o!r}")
        self.allowed_api_base_urls = [u.rstrip("/") for u in self.allowed_api_base_urls]
        for u in self.allowed_api_base_urls:
            if not (u.startswith("https://") or u.startswith("http://localhost") or u.startswith("http://127.0.0.1")):
                raise ValueError(f"API base URL must use HTTPS (plain HTTP only for localhost): {u!r}")
        if self.heartbeat_seconds < 5 or self.process_poll_seconds < 0.5 or self.window_poll_seconds < 0.5:
            raise ValueError("Polling intervals are too small (heartbeat ≥ 5 s, polls ≥ 0.5 s).")
        self.trusted_system_processes = [p.lower() for p in self.trusted_system_processes]
        self.allowlisted_processes = [p.lower() for p in self.allowlisted_processes]
        self.browser_process_names = [p.lower() for p in self.browser_process_names]
        return self

    def resolved_log_dir(self) -> Path:
        if self.log_dir:
            return Path(self.log_dir)
        base = os.environ.get("LOCALAPPDATA") if sys.platform == "win32" else None
        return Path(base) / "SecureHireAgent" / "logs" if base else Path.home() / ".securehire-agent" / "logs"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_config_path() -> Optional[Path]:
    if sys.platform == "win32" and os.environ.get("PROGRAMDATA"):
        return Path(os.environ["PROGRAMDATA"]) / "SecureHireAgent" / "config.json"
    return None


def load_config(path: Optional[str] = None, overrides: Optional[dict[str, Any]] = None) -> AgentConfig:
    """Load defaults ← JSON file (if any) ← explicit overrides. Unknown keys are rejected."""
    data: dict[str, Any] = {}
    p = Path(path) if path else default_config_path()
    if p and p.exists():
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{p}: configuration must be a JSON object")
    data.update(overrides or {})
    known = {f.name for f in fields(AgentConfig)}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
    return AgentConfig(**data).validate()
