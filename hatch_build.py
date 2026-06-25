"""
hatch_build.py — Post-install hook: download spaCy en_core_web_lg model.

Runs automatically after `pip install guardrailprobe` via hatchling's
build hook interface. The spaCy model is required by the Presidio adapter
for PII entity recognition.

Users can skip the download by setting GUARDRAILPROBE_SKIP_SPACY=1.
"""

from __future__ import annotations

import os
import subprocess
import sys

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def install(self) -> None:
        if os.getenv("GUARDRAILPROBE_SKIP_SPACY", "").strip() in ("1", "true", "yes"):
            print("[guardrailprobe] Skipping spaCy model download (GUARDRAILPROBE_SKIP_SPACY set).")
            return

        try:
            import spacy  # noqa: F401
        except ImportError:
            print("[guardrailprobe] spaCy not installed — skipping model download.")
            return

        # Check if the model is already present.
        try:
            import spacy
            spacy.load("en_core_web_lg")
            print("[guardrailprobe] spaCy en_core_web_lg already present.")
            return
        except OSError:
            pass

        print("[guardrailprobe] Downloading spaCy en_core_web_lg (once per install) …")
        subprocess.check_call(
            [sys.executable, "-m", "spacy", "download", "en_core_web_lg"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        print("[guardrailprobe] spaCy en_core_web_lg downloaded.")
