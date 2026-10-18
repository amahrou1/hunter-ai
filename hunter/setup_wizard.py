"""`hunt setup`: asks for each key, checks it, saves it. The operator only
pastes and presses Enter; nothing is edited by hand."""

from __future__ import annotations

import getpass
from typing import Callable

from . import config, models, notify

InputFn = Callable[[str], str]


def _ask_yes(input_fn: InputFn, question: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input_fn(question + suffix).strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes", "j", "ja")


def _model_profile_for_key(settings: dict, key_name: str) -> dict | None:
    for profile in settings["profiles"].values():
        if profile["key_name"] == key_name:
            return profile
    return None


def ask_key(spec: config.KeySpec, current: str, required: bool, settings: dict,
            input_fn: InputFn, secret_fn: InputFn, out: Callable[[str], None],
            probe_fn=models.probe) -> str:
    """Ask for one value until it is valid. Returns the value to store
    ('' means not set)."""
    out("")
    out(f"== {spec.label} ==")
    out(f"   {spec.hint}")
    if current:
        out(f"   Saved now: {config.mask(current)}")
    keep_hint = " (Enter = keep the saved one)" if current else ("" if required else " (Enter = skip)")
    for _ in range(5):
        prompt = f"   Paste it and press Enter{keep_hint}: "
        raw = (input_fn if spec.kind == "url" else secret_fn)(prompt)
        value = config.clean_secret_value(raw)
        if not value:
            if current:
                out("   Kept the saved value.")
                return current
            if not required:
                out("   Skipped.")
                return ""
            out("   This one is required. Please paste it.")
            continue
        if spec.kind == "url":
            if not notify.valid_webhook(value):
                out("   That does not look like a Discord webhook URL. It must start with "
                    "https://discord.com/api/webhooks/ . Please copy it again.")
                continue
        elif len(value) < 8 or any(ch.isspace() for ch in value):
            out("   That does not look like a key (too short or contains spaces). Please paste it again.")
            continue
        out(f"   Received: {config.mask(value)}")

        profile = _model_profile_for_key(settings, spec.name)
        if profile is not None:
            out("   Checking the key with the provider ...")
            ok, message = probe_fn(profile, value)
            out(f"   Result: {message}")
            if not ok:
                if _ask_yes(input_fn, "   Save this key anyway?", default=False):
                    return value
                continue
        return value
    out("   Too many attempts. Moving on.")
    return current


def run_setup(input_fn: InputFn = input, secret_fn: InputFn = getpass.getpass,
              out: Callable[[str], None] = print, probe_fn=models.probe,
              notifier_factory=notify.Notifier) -> int:
    settings = config.load_settings()
    secrets = config.load_secrets()
    needed_now = models.required_key_names(settings)

    out("hunter-ai setup")
    out("You will be asked for each key. Paste it and press Enter.")
    out("Keys are saved only on this server, in a file only you can read.")
    out("When you paste a key, nothing appears on screen. That is normal.")

    recon_asked = False
    for spec in config.KEY_CATALOG:
        is_model_key = _model_profile_for_key(settings, spec.name) is not None
        is_recon = not spec.required and not is_model_key
        if is_recon and not recon_asked:
            recon_asked = True
            out("")
            if not _ask_yes(input_fn, "Do you want to add or change optional recon keys now "
                            "(Shodan, Chaos, GitHub, SecurityTrails, VirusTotal, urlscan, Censys)?"):
                break
        required = spec.required or spec.name in needed_now
        value = ask_key(spec, secrets.get(spec.name, ""), required, settings,
                        input_fn, secret_fn, out, probe_fn)
        if value:
            secrets[spec.name] = value
        else:
            secrets.pop(spec.name, None)
        config.save_secrets(secrets)

    out("")
    out("Sending a test message to Discord ...")
    notifier = notifier_factory(secrets)
    if notifier.send("Setup complete", "hunter-ai can reach this channel.", "success"):
        out("Discord: message sent. Check the #alerts channel.")
    else:
        out("Discord: the message could not be sent. Run hunt setup again and paste the webhook URL again.")

    missing = sorted(name for name in needed_now if not secrets.get(name))
    out("")
    if missing:
        out("Still missing for the current model profile: " + ", ".join(missing))
        out("Run hunt setup again to add it.")
        return 1
    out("Setup finished. Next, run: hunt doctor")
    return 0
