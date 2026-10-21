"""Launcher used by PyInstaller and for double-click runs: starts the agent with its status window."""
import sys

from agent.main import main

if __name__ == "__main__":
    sys.exit(main())
