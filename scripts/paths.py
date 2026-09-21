import os
import sys
from pathlib import Path


def app_root() -> Path:
    """Folder that holds projects/, config.json and zap_servers.json."""
    env = os.environ.get("SCAN_HOME")
    if env:
        return Path(env).resolve()
    if getattr(sys, "frozen", False):              # running as an .exe
        return Path.cwd()
    return Path(__file__).resolve().parent.parent  # normal python run