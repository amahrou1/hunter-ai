"""The `hunt` launcher must load the installed code even when started from a
folder that contains another package called `hunter` (this happened in the
end-to-end test: tmux was pointed at the wrong copy)."""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_launcher_ignores_current_directory(tmp_path):
    repo = tmp_path / "install"
    shutil.copytree(ROOT / "hunter", repo / "hunter")
    shutil.copytree(ROOT / "bin", repo / "bin")
    (repo / ".venv" / "bin").mkdir(parents=True)
    (repo / ".venv" / "bin" / "python").symlink_to(sys.executable)

    decoy = tmp_path / "elsewhere" / "hunter"
    decoy.mkdir(parents=True)
    (decoy / "__init__.py").write_text("raise SystemExit('decoy package was imported')\n")
    (decoy / "cli.py").write_text("raise SystemExit('decoy package was imported')\n")

    link = tmp_path / "hunt"
    link.symlink_to(repo / "bin" / "hunt")
    proc = subprocess.run([str(link), "version"], cwd=decoy.parent, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("hunter-ai ")
