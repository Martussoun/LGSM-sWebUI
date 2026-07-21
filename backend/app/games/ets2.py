import re
from pathlib import Path
from backend.app.games.base import GameHandler

HOSTNAME_RE = re.compile(r'^\s*lobby_name\s*:\s*"(.+)"', re.MULTILINE)
ALLOWED_EXTENSIONS = {".cfg", ".sii"}

class ETS2Handler(GameHandler):
    shortname = "ets2"

    def lgsm_config_dir(self) -> Path:
        return self.lgsm_root / "ets2server"

    def game_config_dirs(self):
        yield from self.base_dir.rglob(".local/share/Euro Truck Simulator 2")

    def get_display_name(self):
        for cfg_dir in self.game_config_dirs():
            cfg = cfg_dir / "server_config.sii"
            if not cfg.exists():
                continue
            try:
                m = HOSTNAME_RE.search(cfg.read_text(errors="ignore"))
                if m:
                    return m.group(1)
            except Exception:
                pass
        return None

    def is_editable_game_config(self, file: Path) -> bool:
        return file.suffix.lower() in ALLOWED_EXTENSIONS and not file.name.startswith("gamemode_")