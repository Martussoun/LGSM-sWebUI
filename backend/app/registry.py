from __future__ import annotations
import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
import os
import re
from backend.app.linuxgsm import LinuxGSMServer
from backend.app.schemas import ServerInfo
from backend.app.games.games_registry import GAME_HANDLERS
from backend.app.games.base import GameHandler
from enum import Enum

class ServerStatus(str, Enum):
    UNKNOWN = "unknown"
    FREE = "free"
    STARTING = "starting"
    LIVE = "live"
    STOPPING = "stopping"
    ERROR = "error"
    RESERVED = "reserved"

# Regex to detect LGSM scripts and extract the shortname
LGSM_SCRIPT_RE = re.compile(
    r'^(?:.|\n)*^# Project: Linux Game Server Managers - LinuxGSM.*?\n(?:.|\n)*?^shortname=["\']?([a-z0-9]+)["\']?',
    re.MULTILINE
)

# Regex to extract status from details endpoint
STATUS_RE = re.compile(r"Status:\s*(\w+)", re.IGNORECASE)

@dataclass
class RegisteredServer:
    id: str
    name: str
    base_dir: Path
    script_name: str
    shortname: str
    status: str = ServerStatus.UNKNOWN
    handler: Optional[GameHandler] = None

    def instance(self) -> LinuxGSMServer:
        return LinuxGSMServer(self.base_dir, self.script_name)


class ServerRegistry:
    """
    Detects LinuxGSM server scripts and manages game-specific handlers.
    Only scans the current user's home folder, skipping hidden folders.
    """

    def __init__(self, lgsm_root: Optional[Path] = None):
        self.home = Path.home()
        self.scan_root: Path = self.home
        self._servers: Dict[str, RegisteredServer] = {}
        self.lgsm_root = lgsm_root or self._find_lgsm_root()
        self._allocation_lock = asyncio.Lock()

    def _find_lgsm_root(self) -> Optional[Path]:
        """Try to detect LGSM root inside the home folder."""
        for p in [self.home] + list(self.home.parents):
            candidate = p / "lgsm" / "config-lgsm"
            if candidate.exists() and candidate.is_dir():
                return candidate
        return None

    def _is_executable(self, p: Path) -> bool:
        try:
            return p.is_file() and os.access(str(p), os.X_OK)
        except Exception:
            return False

    def _make_id(self, base_dir: Path, script_name: str) -> str:
        return script_name

    def _parse_lgsm_shortname(self, script: Path) -> Optional[str]:
        try:
            text = script.read_text(errors="ignore")
        except Exception:
            return None
        match = LGSM_SCRIPT_RE.search(text)
        return match.group(1) if match else None

    def list(self) -> List[ServerInfo]:
        servers: List[ServerInfo] = []
        for s in self._servers.values():
            servers.append(
                ServerInfo(
                    id=s.id,
                    name=s.name,
                    path=str(s.base_dir),
                    shortname=s.shortname,
                    script=s.script_name,
                    status=s.status
                )
            )
        return servers

    def get(self, server_id: str) -> RegisteredServer:
        if server_id not in self._servers:
            raise KeyError(f"Unknown server id: {server_id}")
        return self._servers[server_id]

    def all_config_paths(self) -> list[dict]:
        results: list[dict] = []
        for s in self._servers.values():
            if not s.handler:
                continue
            try:
                for src in s.handler.config_sources():
                    path = src.path.resolve()
                    if not path.exists():
                        continue
                    results.append({
                        "key": f"{s.id}:{src.key}",
                        "server_id": s.id,
                        "label": src.label,
                        "path": str(path),
                    })
            except Exception:
                continue
        return results

    async def reconcile_unknown(self):
        """
        Resolve servers with UNKNOWN status by querying LGSM details concurrently.
        """
        sem = asyncio.Semaphore(10)  # thread limit
        async def check_server(s):
            async with sem:
                try:
                    details = await asyncio.to_thread(s.instance().details)

                    if isinstance(details, str):
                        details = details.splitlines()

                    status_value = None

                    for line in details:
                        match = STATUS_RE.search(line)
                        if match:
                            status_value = match.group(1).lower()
                            break

                    if status_value in {"running", "started"}:
                        s.status = ServerStatus.LIVE
                    elif status_value == "stopped":
                        s.status = ServerStatus.FREE
                    else:
                        s.status = ServerStatus.UNKNOWN

                except Exception:
                    s.status = ServerStatus.ERROR

        tasks = [
            check_server(s)
            for s in self._servers.values()
            if s.status == ServerStatus.UNKNOWN
        ]

        if tasks:
            await asyncio.gather(*tasks)

    async def reserve_server(self) -> str:
        async with self._allocation_lock:

            for server in self._servers.values():
                if server.status == ServerStatus.FREE:
                    server.status = ServerStatus.RESERVED
                    return server.id

            raise RuntimeError("No free servers available")

    def scan(self) -> List[ServerInfo]:
        """
        Scan home folder for LGSM scripts, skipping hidden folders.
        """
        found: Dict[str, RegisteredServer] = {}

        try:
            for child in self.home.rglob("*"):
                # Skip hidden files/folders
                if any(part.startswith(".") for part in child.relative_to(self.home).parts):
                    continue

                # Limit scan depth to home/* or home/*/* (2 levels)
                if len(child.relative_to(self.home).parts) > 2:
                    continue

                if not self._is_executable(child) or child.suffix != "":
                    continue

                shortname = self._parse_lgsm_shortname(child)
                if not shortname:
                    continue

                handler = None
                handler_cls = GAME_HANDLERS.get(shortname)
                if handler_cls:
                    try:
                        handler = handler_cls(self.home, child.name, lgsm_root=self.lgsm_root)
                    except Exception:
                        handler = None

                name = child.name
                if handler:
                    try:
                        display = handler.get_display_name()
                        if display:
                            name = display
                    except Exception:
                        pass

                server_id = self._make_id(self.home, child.name)

                found[server_id] = RegisteredServer(
                    id=server_id,
                    name=name,
                    base_dir=child.parent,
                    script_name=child.name,
                    shortname=shortname,
                    handler=handler,
                )

        except (PermissionError, OSError):
            pass

        self._servers = found
        return self.list()
