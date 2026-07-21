from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Iterable
import shutil
import datetime


@dataclass(frozen=True)
class ConfigSource:
    key: str
    label: str
    path: Path


class GameHandler(ABC):
    shortname: str  # Game shortname, e.g. "cs2"

    def __init__(self, base_dir: Path, script_name: str, lgsm_root: Optional[Path] = None):
        self.base_dir = base_dir
        self.script_name = script_name
        self.lgsm_root = lgsm_root

    # -----------------------
    # Config source discovery
    # -----------------------
    def config_sources(self) -> list[ConfigSource]:
        """
        Return all available config paths for this server/game as ConfigSource objects,
        with unique stable keys (suitable for aggregation).
        """
        sources: list[ConfigSource] = []

        # LGSM configs
        lgsm_dir = self.lgsm_config_dir()
        if lgsm_dir and lgsm_dir.exists():
            sources.append(
                ConfigSource(
                    key="lgsm",
                    label="LGSM",
                    path=lgsm_dir.resolve(),
                )
            )

        # Game configs (one source per directory, stable key)
        for idx, d in enumerate(self.game_config_dirs()):
            if d.exists():
                sources.append(
                    ConfigSource(
                        key=f"game:{d.resolve().name}:{idx}",  # include index to avoid key collisions
                        label=f"Game ({d.name})",
                        path=d.resolve(),
                    )
                )

        return sources

    # -----------------------
    # Display / identification
    # -----------------------
    @abstractmethod
    def get_display_name(self) -> Optional[str]:
        ...

    # -----------------------
    # LGSM config folder (ONLY editable scope)
    # -----------------------
    @abstractmethod
    def lgsm_config_dir(self) -> Optional[Path]:
        """Return LGSM config directory for this game"""

    # -----------------------
    # Game-specific config folders (server .cfgs)
    # -----------------------
    @abstractmethod
    def game_config_dirs(self) -> Iterable[Path]:
        """Return directories containing game server .cfg files"""

    @abstractmethod
    def is_editable_game_config(self, file: Path) -> bool:
        """Return True if this game config file is allowed to be edited."""
        ...

    # -----------------------
    # Helpers for safety / normalization
    # -----------------------
    def _normalize_text(self, text: str) -> str:
        """
        Convert all line endings to LF, ensure trailing newline,
        reject binary / control content.
        """
        if "\x00" in text:
            raise ValueError("NUL byte detected, refusing to write")

        if any(ord(c) < 9 or (13 < ord(c) < 32) for c in text):
            raise ValueError("Binary content detected, refusing to write")

        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if not text.endswith("\n"):
            text += "\n"
        return text

    def _read_and_normalize(self, file: Path) -> str:
        """Read text file safely, normalize line endings."""
        text = file.read_text(encoding="utf-8", errors="ignore")
        return text.replace("\r\n", "\n").replace("\r", "\n")

    # -----------------------
    # LGSM config management
    # -----------------------
    def list_lgsm_configs(self) -> List[Path]:
        cfg_dir = self.lgsm_config_dir()
        if not cfg_dir or not cfg_dir.exists() or not cfg_dir.is_dir():
            return []

        return [p for p in cfg_dir.iterdir() if p.is_file() and p.suffix == ".cfg"]

    def read_lgsm_config(self, name: str) -> str:
        cfg_dir = self.lgsm_config_dir()
        if not cfg_dir:
            raise ValueError("LGSM config directory not defined")

        file = (cfg_dir / name).resolve()
        self._validate_lgsm_path(file)

        if not file.exists():
            raise FileNotFoundError(f"LGSM config file not found: {file}")

        return self._read_and_normalize(file)

    def write_lgsm_config(self, name: str, content: str) -> None:
        cfg_dir = self.lgsm_config_dir()
        if not cfg_dir:
            raise ValueError("LGSM config directory not defined")

        file = (cfg_dir / name).resolve()
        self._validate_lgsm_path(file)

        if not file.exists():
            raise FileNotFoundError(f"Cannot create new file: {file}")

        # Backup original
        backup_dir = cfg_dir / "backup"
        backup_dir.mkdir(exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy(file, backup_dir / f"{file.name}.{timestamp}.bak")

        content = self._normalize_text(content)
        file.write_text(content, encoding="utf-8")

    # -----------------------
    # Game server config management
    # -----------------------
    def list_game_configs(self) -> List[Path]:
        files: List[Path] = []
        for cfg_root in self.game_config_dirs():
            if cfg_root.exists() and cfg_root.is_dir():
                for p in cfg_root.glob("*"):
                    if p.is_file() and self.is_editable_game_config(p):
                        files.append(p)
        return files

    def read_game_config(self, name_or_path) -> str:
        if isinstance(name_or_path, str):
            file = None
            for cfg_root in self.game_config_dirs():
                candidate = cfg_root / name_or_path
                if candidate.exists() and candidate.is_file():
                    file = candidate
                    break
            if not file:
                raise FileNotFoundError(f"Game config file not found: {name_or_path}")
        else:
            file = name_or_path

        self._validate_editable_game_config(file)
        return self._read_and_normalize(file)

    def write_game_config(self, name_or_path, content: str) -> None:
        if isinstance(name_or_path, str):
            file = None
            for cfg_root in self.game_config_dirs():
                candidate = cfg_root / name_or_path
                if candidate.exists() and candidate.is_file():
                    file = candidate
                    break
            if not file:
                raise FileNotFoundError(f"Cannot create new game config file: {name_or_path}")
        else:
            file = name_or_path

        self._validate_editable_game_config(file)

        # Backup
        backup_dir = file.parent / "backup"
        backup_dir.mkdir(exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy(file, backup_dir / f"{file.name}.{timestamp}.bak")

        content = self._normalize_text(content)
        file.write_text(content, encoding="utf-8")

    # -----------------------
    # Security / validation
    # -----------------------
    def _validate_lgsm_path(self, file: Path) -> None:
        root = self.lgsm_config_dir()
        if not root:
            raise ValueError("LGSM config directory not defined")

        root = root.resolve()
        file = file.resolve()

        if not file.is_relative_to(root):
            raise ValueError(f"Access denied: {file}")

    def _validate_game_path(self, file: Path) -> None:
        allowed_dirs = [r.resolve() for r in self.game_config_dirs() if r.exists()]
        file = file.resolve()

        if not any(file.is_relative_to(d) for d in allowed_dirs):
            raise ValueError(f"Access denied to game config file: {file}")

    def _validate_editable_game_config(self, file: Path) -> None:
        self._validate_game_path(file)
        if not self.is_editable_game_config(file):
            raise ValueError(f"Editing of this game config is forbidden: {file}")
