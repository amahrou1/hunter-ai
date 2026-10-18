"""Phase 00: intake.

Build step 2 version: takes a hashed snapshot of every input file so later
phases (and the final report) can prove exactly which policy and which
accounts the run used. Policy parsing into scope.json arrives in build
step 3 with a new version number, which makes this phase run again.
"""

from __future__ import annotations

import hashlib
import shutil

from .. import state as st
from ..target import INPUT_FILES
from .base import Context, Phase, PhaseResult


class IntakePhase(Phase):
    id = "00-intake"
    name = "Intake: inputs and policy"
    version = "0.1"
    build_step = 3

    def run(self, ctx: Context) -> PhaseResult:
        snapshot = ctx.target.output / "inputs"
        snapshot.mkdir(parents=True, exist_ok=True)
        manifest = {}
        for filename, (required, description) in INPUT_FILES.items():
            source = ctx.target.input_path(filename)
            text = ctx.target.input_text(filename)
            entry = {"present": bool(text), "required": required, "description": description}
            if text:
                entry["sha256"] = hashlib.sha256(text.encode()).hexdigest()
                entry["lines"] = text.count("\n") + 1
                entry["characters"] = len(text)
                shutil.copy2(source, snapshot / filename)
            manifest[filename] = entry
            ctx.log(f"{filename}: {'present, ' + str(entry['lines']) + ' lines' if text else 'not provided'}")
        ctx.write_json("inputs/manifest.json", manifest)

        present = [name for name, entry in manifest.items() if entry["present"]]
        summary = f"Inputs recorded: {', '.join(present)}. Policy parsing is added in build step 3."
        return PhaseResult(st.DONE, summary)
