"""Entry point: ``python -m agent.main [--config path] [--headless] [--port N]``.

Starts the loopback-only local service and the visible status window. Monitoring itself only
begins when the SecureHire extension forwards an authorised assessment session.
"""
from __future__ import annotations

import argparse
import signal
import sys
import threading

from . import __version__
from .assessment_session import SessionManager
from .config import load_config
from .local_api import LocalServer, build_app
from .security_logger import setup_logging
from .status_ui import NOTICE, describe


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="securehire-agent", description="SecureHire Desktop Security Agent")
    p.add_argument("--config", help="Path to a JSON configuration file")
    p.add_argument("--port", type=int, help="Local service port (default 47615)")
    p.add_argument("--headless", action="store_true", help="No window; print status to the console instead")
    p.add_argument("--version", action="version", version=__version__)
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    overrides = {"local_port": args.port} if args.port else {}
    cfg = load_config(args.config, overrides)
    log = setup_logging(cfg)
    log.info("SecureHire agent %s starting (local service on %s:%d)", __version__, cfg.local_host, cfg.local_port)
    if sys.platform != "win32":
        log.warning("Not running on Windows: USB and window monitors will report 'not available'. Process monitoring still works.")

    manager = SessionManager(cfg)
    server = LocalServer(build_app(manager, cfg), cfg)
    if not server.start():
        log.error("Could not start the local service on port %d (is another agent already running?)", cfg.local_port)
        return 2

    stopping = threading.Event()

    def shutdown() -> None:
        if stopping.is_set():
            return
        stopping.set()
        if manager.active:
            manager.end("candidate_closed_agent", user_initiated=True)
        server.stop()
        log.info("Agent stopped")

    signal.signal(signal.SIGINT, lambda *_: shutdown())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: shutdown())

    if not args.headless:
        try:
            from .status_ui import StatusWindow
            StatusWindow(manager, on_exit=shutdown).run()
            shutdown()
            return 0
        except Exception as e:  # noqa: BLE001 — e.g. no display; fall back to the console
            log.warning("Status window unavailable (%s); using console status", e)

    print(NOTICE)
    print("Press Ctrl+C to exit. Exiting during an assessment is reported to the recruiter.")
    last = None
    while not stopping.wait(2.0):
        d = describe(manager.status())
        line = f"[{d['headline']}] {d['connection']} | monitors: {d['monitors'] or '-'} | pending: {d['delivery'].get('pending', 0)}"
        if line != last:
            print(line, flush=True)
            last = line
    return 0


if __name__ == "__main__":
    sys.exit(main())
