import re
import json
from pathlib import Path
from backend.app.games.base import GameHandler

HOSTNAME_RE = re.compile(r'^hostname\s+"(.+)"', re.MULTILINE)
ALLOWED_EXTENSIONS = {".cfg", ".temcfg", ".json"}

class CS2Handler(GameHandler):
    shortname = "cs2"

    def lgsm_config_dir(self) -> Path:
        return self.lgsm_root / "cs2server"

    def get_lgsm_config_path(self) -> Path:
        return self.lgsm_config_dir() / f"{self.script_name}.cfg"

    def game_config_dirs(self):
        yield from self.base_dir.rglob("serverfiles/game/csgo/cfg")

    def matches_dir(self) -> Path:
        for cfg_dir in self.game_config_dirs():
            matches = cfg_dir / "matches"
            matches.mkdir(parents=True, exist_ok=True)
            return matches
        raise RuntimeError("Could not resolve matches directory")

    def get_display_name(self):
        for cfg_dir in self.game_config_dirs():
            cfg = cfg_dir / f"{self.script_name}.cfg"
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
        return (
            file.suffix.lower() in ALLOWED_EXTENSIONS
            and not file.name.startswith("gamemode_")
        )

    # -------------------------
    # PREP ENTRYPOINT
    # -------------------------

    def prepare(self, srv, payload: dict):
        if payload.get("validate", True):
            self.validate_payload(payload)

        self.apply_map_settings(payload)
        self.set_hostname(payload)
        self.write_match_json(payload)
        self.apply_lgsm_settings(payload)

    # -------------------------
    # VALIDATION
    # -------------------------

    def validate_payload(self, payload: dict):
        required = ["match_id", "server_id", "template", "match"]

        for key in required:
            if key not in payload:
                raise RuntimeError(f"Missing required field: {key}")

        max_players = payload.get("max_players")
        if not isinstance(max_players, int):
            raise RuntimeError("max_players must be an integer")

        if not (2 <= max_players <= 64):
            raise RuntimeError("max_players must be between 2 and 64")

        map_name = payload.get("map")
        workshop_id = payload.get("workshop_id")

        if not map_name:
            payload["map"] = "de_dust2"

        if payload.get("map") and not isinstance(payload["map"], str):
            raise RuntimeError("map must be a string")

        if workshop_id:
            if not isinstance(workshop_id, (str, int)):
                raise RuntimeError("workshop_id must be string or int")
            payload["workshop_id"] = str(workshop_id)

        match = payload["match"]

        for side in ["teamA", "teamB"]:
            if side not in match:
                raise RuntimeError(f"{side} missing in match data")

            team = match[side]

            if "players" not in team or not isinstance(team["players"], list):
                raise RuntimeError(f"{side}.players must be a list")

            if "preferredSide" not in team:
                raise RuntimeError(f"{side}.preferredSide missing")

    # -------------------------
    # MAP / WORKSHOP
    # -------------------------

    def apply_map_settings(self, payload: dict):
        map_name = payload.get("map")
        workshop_id = payload.get("workshop_id")

        main_cfg = f"{self.script_name}.cfg"
        content = self.read_game_config(main_cfg)

        lines = content.splitlines()
        new_lines = []

        for line in lines:
            stripped = line.strip()

            if stripped.startswith("map "):
                continue
            if stripped.startswith("host_workshop_map "):
                continue

            new_lines.append(line)

        new_lines.append(f'map "{map_name}"')

        if workshop_id:
            new_lines.append(f'host_workshop_map "{workshop_id}"')

        self.write_game_config(main_cfg, "\n".join(new_lines))

    # -------------------------
    # HOSTNAME
    # -------------------------

    def set_hostname(self, payload: dict):
        match_id = payload["match_id"]
        server_id = payload["server_id"]
        template = payload["template"]

        hostname_value = f'CS2|mid={match_id}|sid={server_id}|cfg={template}'

        main_cfg = f"{self.script_name}.cfg"
        content = self.read_game_config(main_cfg)

        if HOSTNAME_RE.search(content):
            content = HOSTNAME_RE.sub(f'hostname "{hostname_value}"', content)
        else:
            content += f'\nhostname "{hostname_value}"\n'

        self.write_game_config(main_cfg, content)

    # -------------------------
    # MATCH JSON
    # -------------------------

    def write_match_json(self, payload: dict):
        match_id = payload["match_id"]
        match_data = payload["match"]

        path = self.matches_dir() / f"{match_id}.json"

        def normalize_players(players):
            out = []
            for p in players:
                if isinstance(p, int):
                    out.append(p)
                elif isinstance(p, str) and p.isdigit():
                    out.append(int(p))
                else:
                    raise RuntimeError(f"Invalid SteamID: {p}")
            return out

        output = {
            "teamA": {
                "team_id": match_data["teamA"].get("team_id", ""),
                "name": match_data["teamA"].get("name", ""),
                "players": normalize_players(match_data["teamA"].get("players", [])),
                "preferredSide": match_data["teamA"].get("preferredSide"),
            },
            "teamB": {
                "team_id": match_data["teamB"].get("team_id", ""),
                "name": match_data["teamB"].get("name", ""),
                "players": normalize_players(match_data["teamB"].get("players", [])),
                "preferredSide": match_data["teamB"].get("preferredSide"),
            },
            "enforce": match_data.get("enforce", True),
        }

        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(output, indent=2))
        tmp.replace(path)

    # -------------------------
    # LGSM CONFIG
    # -------------------------

    def apply_lgsm_settings(self, payload: dict):
        max_players = payload.get("max_players")
        if max_players is None:
            return

        cfg_path = self.get_lgsm_config_path()

        if not cfg_path.exists():
            raise RuntimeError(f"LGSM config not found: {cfg_path}")

        content = cfg_path.read_text()

        lines = content.splitlines()
        updated = False

        for i, line in enumerate(lines):
            if line.strip().startswith("maxplayers"):
                lines[i] = f'maxplayers="{max_players}"'
                updated = True
                break

        if not updated:
            lines.append(f'maxplayers="{max_players}"')

        lines.append(f'# match_id={payload.get("match_id")}')

        cfg_path.write_text("\n".join(lines))