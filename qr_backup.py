from __future__ import annotations

import os
import re
import shutil
import stat
import sys
from difflib import get_close_matches
from typing import Dict, Optional, Tuple

try:
    import qrcode
except ImportError:
    raise SystemExit(
        "Missing dependency: qrcode\n"
        "Install with: pip install 'qrcode[pil]'"
    )

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MNEMONIC_ENV = "VANITY_MNEMONIC"
PRIVATE_KEY_ENV = "VANITY_PRIVATE_KEY"

BIP39_WORDLIST_SIZE = 2048
VALID_WORD_COUNTS = (12, 15, 18, 21, 24)

TARGET_PIXELS = 2000
BORDER_MODULES = 4
MAX_SECRET_LENGTH = 1000

HEX_KEY = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")


def _is_tty(stream: object) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def erase_typed_line(prompt: str, typed: str) -> None:
    if not sys.stdout.isatty():
        return
    width = shutil.get_terminal_size((80, 24)).columns or 80
    rows = max(1, -(-(len(prompt) + len(typed)) // width))
    sys.stdout.write("\033[F\033[2K" * rows)
    sys.stdout.flush()


def prompt_choice(title: str, options: Dict[str, str], missing_message: str) -> str:
    if not _is_tty(sys.stdin):
        raise SystemExit(missing_message)
    order = list(options)
    print(f"\n{title}")
    for position, key in enumerate(order, start=1):
        print(f"  {position}) {options[key]}")
    while True:
        raw = input("Choice: ").strip()
        if raw in options:
            return raw
        if raw.isdigit() and 1 <= int(raw) <= len(order):
            return order[int(raw) - 1]
        print(f"  Enter a number from 1 to {len(order)}.")


def prompt_yes_no(label: str, default: bool = False) -> bool:
    if not _is_tty(sys.stdin):
        return default
    raw = input(f"{label} ({'Y/n' if default else 'y/N'}): ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def normalize_mnemonic(value: str) -> str:
    return " ".join(value.split()).lower()


def read_secret(prompt: str, env_var: str, empty_message: str) -> Tuple[str, bool]:
    from_env = os.environ.get(env_var)
    if from_env:
        return from_env, False
    entered = input(prompt)
    erase_typed_line(prompt, entered)
    if not entered.strip():
        raise SystemExit(empty_message)
    if len(entered) > MAX_SECRET_LENGTH:
        raise SystemExit(f"Input is longer than {MAX_SECRET_LENGTH} characters.")
    return entered, True


def validate_seed_phrase(mnemonic: str) -> str:
    try:
        from mnemonic import Mnemonic
    except ImportError:
        raise SystemExit(
            "Missing dependency: mnemonic\n"
            "Install with: pip install mnemonic"
        )

    mnemo = Mnemonic("english")
    if len(mnemo.wordlist) != BIP39_WORDLIST_SIZE:
        raise SystemExit(
            f"BIP39 wordlist is corrupt: expected {BIP39_WORDLIST_SIZE} words, "
            f"found {len(mnemo.wordlist)}. Reinstall the 'mnemonic' package."
        )

    words = mnemonic.split()
    if not words:
        raise SystemExit("No seed phrase entered.")
    if len(words) not in VALID_WORD_COUNTS:
        raise SystemExit(
            f"A BIP39 seed phrase must have {', '.join(str(n) for n in VALID_WORD_COUNTS)} words; "
            f"this one has {len(words)}."
        )

    wordlist = set(mnemo.wordlist)
    unknown = [(position, word) for position, word in enumerate(words, start=1) if word not in wordlist]
    if unknown:
        lines = [f"These words are not in the official BIP39 English wordlist ({BIP39_WORDLIST_SIZE} words):"]
        for position, word in unknown:
            suggestions = get_close_matches(word, mnemo.wordlist, n=3, cutoff=0.6)
            hint = f"   did you mean: {', '.join(suggestions)}?" if suggestions else ""
            lines.append(f"  word {position}: {word!r}{hint}")
        lines.append("")
        lines.append("Only real BIP39 words are accepted. Random or misspelled words cannot")
        lines.append("belong to any wallet, so there is nothing worth backing up.")
        raise SystemExit("\n".join(lines))

    if not mnemo.check(mnemonic):
        raise SystemExit(
            "Seed phrase checksum is invalid.\n"
            "Every word is a real BIP39 word, but the phrase as a whole is not valid -- "
            "usually a wrong,\nmissing, or transposed word. Check the words and their order, then try again."
        )
    return mnemonic


def read_seed_phrase() -> str:
    entered, interactive = read_secret(
        "Enter seed phrase: ", MNEMONIC_ENV, "No seed phrase entered."
    )
    phrase = normalize_mnemonic(entered)
    if interactive:
        print(f"Seed phrase received: {len(phrase.split())} words")
    return validate_seed_phrase(phrase)


def describe_private_key(key: str) -> Optional[str]:
    if HEX_KEY.match(key):
        return "EVM private key (32 bytes, hex)"
    if set(key) <= set(BASE58_ALPHABET):
        if 86 <= len(key) <= 90:
            return "Solana private key (64 bytes, base58)"
        if 43 <= len(key) <= 45:
            return "32-byte base58 key"
    return None


def read_private_key() -> str:
    entered, interactive = read_secret(
        "Enter private key: ", PRIVATE_KEY_ENV, "No private key entered."
    )
    key = entered.strip()
    kind = describe_private_key(key)
    if kind is None:
        print("\nThat does not look like a private key this tool recognises.")
        print("Recognised formats: 64 hex characters (EVM), or 87-88 base58 characters (Solana).")
        if not prompt_yes_no("Encode it anyway, exactly as typed?", False):
            raise SystemExit("Cancelled.")
    elif interactive:
        print(f"Private key received: {kind}")
    return key


MAX_FILENAME_LENGTH = 64
MAX_FILENAME_WORDS = 4


def resolve_output_path(name: str) -> str:
    name = os.path.basename(name.strip()) or "keys"
    if name.lower().endswith(".png"):
        name = name[:-4]
    name = name.strip()
    if not name:
        raise SystemExit("File name cannot be empty.")
    if name.startswith("."):
        raise SystemExit("File name cannot start with a dot.")
    if len(name) > MAX_FILENAME_LENGTH or len(name.split()) > MAX_FILENAME_WORDS:
        raise SystemExit(
            "That looks like a secret, not a file name.\n"
            "Nothing was written. A seed phrase or key in a file name is stored on disk in\n"
            "plain text, so this prompt only accepts short names such as 'keys'."
        )
    return os.path.abspath(f"{name}.png")


def build_qr(payload: str):
    probe = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        border=BORDER_MODULES,
    )
    probe.add_data(payload)
    probe.make(fit=True)

    total_modules = probe.modules_count + 2 * BORDER_MODULES
    box_size = max(4, -(-TARGET_PIXELS // total_modules))

    final = qrcode.QRCode(
        version=probe.version,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=box_size,
        border=BORDER_MODULES,
    )
    final.add_data(payload)
    final.make(fit=True)
    return final.make_image(fill_color="black", back_color="white")


def verify_saved_qr(path: str, payload: str) -> Optional[bool]:
    try:
        import cv2
    except ImportError:
        return None
    try:
        decoded, _, _ = cv2.QRCodeDetector().detectAndDecode(cv2.imread(path))
    except Exception:
        return None
    if not decoded:
        return None
    return decoded == payload


def write_qr(path: str, payload: str) -> None:
    image = build_qr(payload)
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(handle, "wb") as stream:
            image.save(stream, format="PNG")
    except Exception:
        if os.path.exists(path):
            os.remove(path)
        raise
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def main() -> int:
    kind = prompt_choice(
        "What are you encoding?",
        {"seed": "Seed phrase", "key": "Private key"},
        "No input type selected. Run this in an interactive terminal.",
    )

    payload = read_seed_phrase() if kind == "seed" else read_private_key()

    name = input("File name [keys]: ").strip() if _is_tty(sys.stdin) else ""
    path = resolve_output_path(name or "keys")

    if os.path.exists(path):
        print(f"\n{path} already exists.")
        if not prompt_yes_no("Overwrite it?", False):
            raise SystemExit("Cancelled.")

    write_qr(path, payload)

    print(f"\nSaved  : {path}")
    if verify_saved_qr(path, payload) is False:
        print("WARNING: the saved image did not decode back to what you entered. Do not rely on it.")
        return 1

    print("\nAnyone who can see this image controls the wallet. Print it, store it offline,")
    print("then delete the file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
