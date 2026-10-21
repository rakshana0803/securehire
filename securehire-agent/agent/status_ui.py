"""Visible status window (Tkinter, ships with Python on Windows).

The agent is never hidden: while it runs, this window (with a taskbar button) shows whether an
assessment is being monitored, what each monitor is doing, the connection to SecureHire, and
the recent observations — the same ones the recruiter will see. Closing it exits the agent;
during an assessment the candidate is told that this interruption will be reported.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Callable

from .assessment_session import SessionManager

log = logging.getLogger("securehire.ui")

NOTICE = ("SecureHire Desktop Security Agent. During an authorised SecureHire assessment it records USB device "
          "connections, newly started applications and metadata of always-on-top windows (size, position, style). "
          "It never reads files, keystrokes, passwords, window contents or the screen. Monitoring starts only when "
          "you begin an assessment and stops when it ends.")

MONITOR_LABEL = {"active": "Active", "starting": "Starting…", "unsupported": "Not available", "error": "Error — retrying",
                 "disabled": "Disabled by policy", "stopped": "Stopped"}


def describe(status: dict) -> dict:
    """Turn a SessionManager.status() snapshot into display strings. Pure (used by the UI and the console)."""
    s = status.get("session") or {}
    active = status.get("active")
    conn = s.get("connection")
    return {
        "headline": "Monitoring this assessment" if active else ("Assessment monitoring ended" if s else "Idle — waiting for an assessment"),
        "assessment": s.get("assessmentTitle") or ("—" if not s else s.get("sessionId", "—")),
        "connection": {"online": "Connected to SecureHire", "offline": "Offline — events are queued and will be sent when back online",
                       "connecting": "Connecting…", "ended": "Session closed"}.get(conn, "—"),
        "monitors": {k: MONITOR_LABEL.get(v, v) for k, v in (s.get("monitors") or {}).items()},
        "delivery": s.get("delivery") or {},
        "error": (s.get("delivery") or {}).get("lastError"),
    }


class StatusWindow:
    def __init__(self, manager: SessionManager, on_exit: Callable[[], None]):
        import tkinter as tk
        from tkinter import messagebox, ttk
        self.tk, self.messagebox = tk, messagebox
        self.manager = manager
        self.on_exit = on_exit
        self.root = tk.Tk()
        self.root.title("SecureHire Security Agent")
        self.root.geometry("520x560")
        self.root.minsize(460, 480)
        self.root.protocol("WM_DELETE_WINDOW", self.request_exit)
        pad = {"padx": 14, "pady": 4}
        tk.Label(self.root, text="SecureHire Security Agent", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=14, pady=(12, 0))
        tk.Label(self.root, text=NOTICE, wraplength=490, justify="left", fg="#475569", font=("Segoe UI", 9)).pack(anchor="w", **pad)
        self.headline = tk.Label(self.root, text="", font=("Segoe UI", 11, "bold"))
        self.headline.pack(anchor="w", padx=14, pady=(8, 2))
        self.info = tk.Label(self.root, text="", justify="left", font=("Segoe UI", 9))
        self.info.pack(anchor="w", **pad)
        ttk.Separator(self.root).pack(fill="x", padx=14, pady=6)
        tk.Label(self.root, text="Recent observations (also visible to the recruiter)", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=14)
        frame = tk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=14, pady=4)
        self.events = tk.Listbox(frame, font=("Segoe UI", 9), activestyle="none")
        sb = tk.Scrollbar(frame, command=self.events.yview)
        self.events.configure(yscrollcommand=sb.set)
        self.events.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        tk.Button(self.root, text="Exit agent", command=self.request_exit).pack(anchor="e", padx=14, pady=10)
        self._last_seq = -1
        self.refresh()

    def refresh(self) -> None:
        try:
            status = self.manager.status()
            d = describe(status)
            self.headline.configure(text=("● " if status.get("active") else "○ ") + d["headline"],
                                    fg="#16A34A" if status.get("active") else "#64748B")
            mons = ", ".join(f"{k}: {v}" for k, v in d["monitors"].items()) or "—"
            dl = d["delivery"]
            lines = [f"Assessment: {d['assessment']}", f"SecureHire: {d['connection']}", f"Monitors: {mons}",
                     f"Events sent: {dl.get('delivered', 0)} · waiting: {dl.get('pending', 0)}" + (f" · dropped: {dl['dropped']}" if dl.get("dropped") else "")]
            if d["error"]:
                lines.append(f"Last problem: {d['error']}")
            self.info.configure(text="\n".join(lines))
            evs = self.manager.recent_events(since=0, limit=100)
            seq = evs[-1]["localId"] if evs else 0
            if seq != self._last_seq:
                self._last_seq = seq
                self.events.delete(0, "end")
                for e in reversed(evs):
                    t = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
                    flag = "REVIEW · " if e["priority"] == "review" else ""
                    self.events.insert("end", f"{t}  {flag}{e['explanation']}")
        except Exception:  # noqa: BLE001 — the UI must keep running
            log.exception("UI refresh failed")
        self.root.after(1000, self.refresh)

    def request_exit(self) -> None:
        if self.manager.active:
            ok = self.messagebox.askyesno(
                "Assessment in progress",
                "An assessment is being monitored right now.\n\nIf you close the agent, desktop monitoring stops and this "
                "interruption will be reported to the recruiter, as described in the assessment policy.\n\nClose the agent anyway?",
                icon="warning")
            if not ok:
                return
            threading.Thread(target=self.manager.end, args=("candidate_closed_agent", True), daemon=True).start()
            self.root.after(1500, self._quit)
            return
        self._quit()

    def _quit(self) -> None:
        self.on_exit()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()
