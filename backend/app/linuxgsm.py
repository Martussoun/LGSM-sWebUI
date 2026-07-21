import subprocess
from pathlib import Path
import re
import json
from typing import Iterator

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s or "")

class LinuxGSMServer:
    def __init__(self, base_dir: Path, script_name: str):
        self.base_dir = base_dir
        self.script = base_dir / script_name

    def runonce(self, args: list[str], timeout: int = 30) -> str:
        proc = subprocess.run(
            [str(self.script), *args],
            cwd=self.base_dir,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        stdout = _strip_ansi(proc.stdout or "")
        stderr = _strip_ansi(proc.stderr or "")
        text = (stdout or stderr).strip()
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

        if proc.returncode != 0:
            raise RuntimeError(text if text else f"Command failed: {args}")

        return lines

    def stream(self, args: list[str]) -> Iterator[str]:
        proc = subprocess.Popen(
            [str(self.script), *args],
            cwd=self.base_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        assert proc.stdout is not None

        for line in proc.stdout:
            clean = _strip_ansi(line).strip()
            if not clean:
                continue

            yield f"data: {json.dumps({'type': 'log', 'message': clean})}\n\n"

        proc.wait()

        yield f"data: {json.dumps({'type': 'exit', 'code': proc.returncode})}\n\n"

    def start(self): return self.runonce(["start"])
    def stop(self): return self.runonce(["stop"])
    def restart(self): return self.runonce(["restart"])
    def details(self): return self.runonce(["details"])
    def update(self): return self.runonce(["update"])
    def force_update(self): return self.runonce(["force-update"])
    def check_update(self): return self.runonce(["check-update"])
    def validate(self): return self.runonce(["validate"])

    def start_stream(self): return self.stream(["start"])
    def stop_stream(self): return self.stream(["stop"])
    def restart_stream(self): return self.stream(["restart"])
    def details_stream(self): return self.stream(["details"])
    def check_update_stream(self): return self.stream(["check-update"])
    def update_stream(self): return self.stream(["update"])
    def force_update_stream(self): return self.stream(["force-update"])
    def validate_stream(self): return self.stream(["validate"])
