"""Bounded local logging. Tokens are redacted before anything is written."""
from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler

from .config import AgentConfig

_SECRET_PATTERNS = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.I),
    re.compile(r'("?(?:agentToken|controlToken|token)"?\s*[:=]\s*"?)[A-Za-z0-9._~+/=-]{8,}', re.I),
]


def redact(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub(r"\1[redacted]", text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(str(record.getMessage()))
        record.args = ()
        return True


def setup_logging(cfg: AgentConfig, console: bool = True) -> logging.Logger:
    logger = logging.getLogger("securehire")
    if getattr(logger, "_securehire_configured", False):
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    redactor = RedactingFilter()
    try:
        log_dir = cfg.resolved_log_dir()
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_dir / "agent.log", maxBytes=cfg.log_max_bytes, backupCount=cfg.log_backups, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.addFilter(redactor)
        logger.addHandler(fh)
    except OSError as e:  # logging must never stop the agent
        logging.getLogger(__name__).warning("File logging unavailable: %s", e)
    if console:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        sh.addFilter(redactor)
        logger.addHandler(sh)
    logger._securehire_configured = True  # type: ignore[attr-defined]
    return logger
