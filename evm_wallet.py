from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import queue
import re
import shutil
import signal
import stat
import struct
import sys
import time
import hashlib
import hmac
from dataclasses import dataclass
from difflib import get_close_matches
from getpass import getpass
from multiprocessing.queues import Queue as MPQueue
from multiprocessing.synchronize import Event as MPEvent
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

try:
    from mnemonic import Mnemonic
    from eth_keys import keys
    from eth_utils import to_checksum_address
except ImportError as error:
    raise SystemExit(
        f"Missing dependency: {error.name}\n"
        "Install with: pip install mnemonic eth-keys eth-utils 'eth-hash[pycryptodome]' coincurve"
    )

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HARDENED = 0x80000000
MAX_INDEX = HARDENED - 1
COIN = 60

HEX_ALPHABET = "0123456789abcdefABCDEF"
MNEMONIC_ENV = "VANITY_MNEMONIC"
PASSPHRASE_ENV = "VANITY_PASSPHRASE"

BIP39_WORDLIST_SIZE = 2048
VALID_WORD_COUNTS = (12, 15, 18, 21, 24)

MAX_PATTERN_LENGTH = 40
PROGRESS_CHECK_EVERY = 256
PROGRESS_SECONDS = 0.5
QUEUE_TIMEOUT = 0.25
SHUTDOWN_GRACE = 5.0
JOIN_TIMEOUT = 2.0
REAP_AFTER_IDLE = 1.0

HIT = "hit"
PROGRESS = "progress"
DONE = "done"
FAILED = "failed"

Message = Tuple[Any, ...]


class Level(NamedTuple):
    label: str
    prefix: Tuple[int, ...]
    tail: Callable[[int], Tuple[int, ...]]


LEVELS: Dict[str, Level] = {
    "account": Level(
        "m/44'/60'/i'/0/0",
        (44 | HARDENED, COIN | HARDENED),
        lambda index: (index | HARDENED, 0, 0),
    ),
    "change": Level(
        "m/44'/60'/0'/i/0",
        (44 | HARDENED, COIN | HARDENED, HARDENED),
        lambda index: (index, 0),
    ),
    "index": Level(
        "m/44'/60'/0'/0/i",
        (44 | HARDENED, COIN | HARDENED, HARDENED, 0),
        lambda index: (index,),
    ),
}


def pattern_forms(text: str, case_sensitive: bool) -> Tuple[str, ...]:
    if not text:
        return ()
    if not case_sensitive:
        return (text.lower(),)
    return tuple(dict.fromkeys((text.lower(), text.upper())))


@dataclass(frozen=True)
class Pattern:
    prefix: str
    suffix: str
    case_sensitive: bool
    prefix_forms: Tuple[str, ...]
    suffix_forms: Tuple[str, ...]

    @classmethod
    def create(cls, prefix: str, suffix: str, case_sensitive: bool) -> "Pattern":
        prefix = prefix.strip()
        suffix = suffix.strip()
        if not case_sensitive:
            prefix = prefix.lower()
            suffix = suffix.lower()
        return cls(
            prefix,
            suffix,
            case_sensitive,
            pattern_forms(prefix, case_sensitive),
            pattern_forms(suffix, case_sensitive),
        )

    @property
    def active(self) -> bool:
        return bool(self.prefix or self.suffix)

    def matches(self, address: str) -> bool:
        if not self.prefix_forms and not self.suffix_forms:
            return True
        if self.prefix_forms and address.startswith(self.prefix_forms):
            return True
        return bool(self.suffix_forms) and address.endswith(self.suffix_forms)

    def describe(self) -> str:
        if not self.active:
            return "every address (no pattern)"
        parts = []
        if self.prefix:
            parts.append(f"prefix {self.prefix!r}")
        if self.suffix:
            parts.append(f"suffix {self.suffix!r}")
        mode = "case-sensitive" if self.case_sensitive else "case-insensitive"
        return f"{' OR '.join(parts)} ({mode})"


@dataclass(frozen=True)
class SearchConfig:
    seed: bytes
    level: str
    label: str
    pattern: Pattern
    start: int
    end: int
    limit: int
    workers: int
    output: Optional[str]
    include_private_keys: bool


@dataclass
class SearchResult:
    hits: List[Tuple[int, str, str]]
    checked: int
    elapsed: float
    resume_index: int
    interrupted: bool
    failures: List[str]


_COUNT_PATTERN = re.compile(r"^(\d+)(?:\.(\d+))?([kmb]?)$")
_MULTIPLIERS = {"": 1, "k": 1_000, "m": 1_000_000, "b": 1_000_000_000}


def parse_amount(value: str) -> int:
    cleaned = value.strip().lower().replace(",", "").replace("_", "")
    match = _COUNT_PATTERN.match(cleaned)
    if match is None:
        raise ValueError(f"invalid number {value!r}; use forms like 1000, 100k, 5m, 2b")
    whole, fraction, unit = match.groups()
    multiplier = _MULTIPLIERS[unit]
    amount = int(whole) * multiplier
    if fraction:
        amount += int(fraction) * multiplier // (10 ** len(fraction))
    return amount


def parse_index(value: str) -> int:
    amount = parse_amount(value)
    if amount > MAX_INDEX:
        raise ValueError(f"index {amount:,} exceeds the maximum derivation index {MAX_INDEX:,}")
    return amount


def format_count(value: int) -> str:
    for size, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if value >= size and value % size == 0:
            return f"{value // size}{suffix}"
    return f"{value:,}"


def format_duration(seconds: float) -> str:
    if seconds != seconds or seconds in (float("inf"), float("-inf")) or seconds < 0:
        return "--:--:--"
    hours, rest = divmod(int(seconds), 3600)
    minutes, secs = divmod(rest, 60)
    if hours > 99:
        return "99:59:59+"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def format_attempts(expected: float) -> str:
    if expected != expected or expected in (float("inf"), float("-inf")):
        return "impossible"
    if expected >= 1e15:
        return f"{expected:.3e}"
    return f"{int(expected):,}"


def format_path(label: str, index: int) -> str:
    return label.replace("i", str(index))


def normalize_mnemonic(value: str) -> str:
    return " ".join(value.split()).lower()


def erase_typed_line(prompt: str, typed: str) -> None:
    if not sys.stdout.isatty():
        return
    width = shutil.get_terminal_size((80, 24)).columns or 80
    rows = max(1, -(-(len(prompt) + len(typed)) // width))
    sys.stdout.write("\033[F\033[2K" * rows)
    sys.stdout.flush()


def read_mnemonic() -> str:
    from_env = os.environ.get(MNEMONIC_ENV)
    if from_env:
        return normalize_mnemonic(from_env)
    if not sys.stdin.isatty():
        piped = sys.stdin.readline()
        if not piped.strip():
            raise SystemExit("No mnemonic received on stdin.")
        return normalize_mnemonic(piped)

    prompt = "Enter seed phrase: "
    entered = input(prompt)
    erase_typed_line(prompt, entered)
    if not entered.strip():
        raise SystemExit("No seed phrase entered.")
    phrase = normalize_mnemonic(entered)
    print(f"Seed phrase received: {len(phrase.split())} words")
    return phrase


def read_passphrase(requested: bool) -> str:
    from_env = os.environ.get(PASSPHRASE_ENV)
    if from_env is not None:
        return from_env
    if not requested:
        return ""
    if not sys.stdin.isatty():
        raise SystemExit("--passphrase-prompt needs a terminal, or set VANITY_PASSPHRASE.")
    first = getpass("Enter BIP39 passphrase (input hidden): ")
    second = getpass("Confirm BIP39 passphrase: ")
    if first != second:
        raise SystemExit("Passphrases did not match.")
    return first


def validate_mnemonic_words(mnemonic: str, mnemo: Mnemonic) -> List[str]:
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
        lines.append("belong to any wallet, so no addresses will be derived from them.")
        raise SystemExit("\n".join(lines))
    return words


def load_seed(mnemonic: str, passphrase: str) -> bytes:
    mnemo = Mnemonic("english")
    validate_mnemonic_words(mnemonic, mnemo)
    if not mnemo.check(mnemonic):
        raise SystemExit(
            "Seed phrase checksum is invalid.\n"
            "Every word is a real BIP39 word, but the phrase as a whole is not valid -- "
            "usually a wrong,\nmissing, or transposed word. Check the words and their order, then try again."
        )
    return mnemo.to_seed(mnemonic, passphrase)


def validate_pattern(text: str, case_sensitive: bool, name: str) -> str:
    if len(text) > MAX_PATTERN_LENGTH:
        raise SystemExit(f"{name} is longer than {MAX_PATTERN_LENGTH} characters.")
    if not text:
        return text
    allowed = set(HEX_ALPHABET) if case_sensitive else {char.lower() for char in HEX_ALPHABET}
    forms = pattern_forms(text, case_sensitive)
    if any(all(char in allowed for char in form) for form in forms):
        return text
    invalid = sorted({char for form in forms for char in form if char not in allowed})
    raise SystemExit(f"{name} contains non-hex characters: {''.join(invalid)}")


def clean_pattern(text: str) -> str:
    text = text.strip()
    return text[2:] if text.lower().startswith("0x") else text


def char_probability(character: str, case_sensitive: bool) -> float:
    lowered = character.lower()
    if lowered not in "0123456789abcdef":
        return 0.0
    if not case_sensitive or lowered.isdigit():
        return 1.0 / 16.0
    return 1.0 / 32.0


def expected_attempts(pattern: Pattern) -> float:
    def form_probability(text: str) -> float:
        total = 1.0
        for character in text:
            total *= char_probability(character, pattern.case_sensitive)
        return total

    def sequence(forms: Tuple[str, ...]) -> float:
        return sum(form_probability(form) for form in forms)

    prefix = sequence(pattern.prefix_forms)
    suffix = sequence(pattern.suffix_forms)
    probability = prefix + suffix - prefix * suffix
    return 1.0 / probability if probability > 0.0 else float("inf")


def compress_public_key(private_key: bytes) -> bytes:
    public = keys.PrivateKey(private_key).public_key.to_bytes()
    return (b"\x03" if public[63] & 1 else b"\x02") + public[:32]


class Node:
    __slots__ = ("key", "chain", "_compressed")

    def __init__(self, key: bytes, chain: bytes) -> None:
        self.key = key
        self.chain = chain
        self._compressed: Optional[bytes] = None

    def compressed(self) -> bytes:
        if self._compressed is None:
            self._compressed = compress_public_key(self.key)
        return self._compressed

    def child(self, index: int) -> "Node":
        if index & HARDENED:
            data = b"\x00" + self.key + struct.pack(">I", index)
        else:
            data = self.compressed() + struct.pack(">I", index)
        digest = hmac.new(self.chain, data, hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        if tweak >= SECP256K1_ORDER:
            raise ValueError(f"invalid BIP32 tweak at index {index}")
        child_key = (tweak + int.from_bytes(self.key, "big")) % SECP256K1_ORDER
        if child_key == 0:
            raise ValueError(f"invalid BIP32 child key at index {index}")
        return Node(child_key.to_bytes(32, "big"), digest[32:])


def master_node(seed: bytes) -> Node:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(digest[:32], "big")
    if key == 0 or key >= SECP256K1_ORDER:
        raise ValueError("seed produced an invalid BIP32 master key")
    return Node(digest[:32], digest[32:])


def address_hex(private_key: bytes) -> str:
    return keys.PrivateKey(private_key).public_key.to_address()[2:]


class EvmDeriver:
    def __init__(self, seed: bytes, level_key: str, checksum: bool) -> None:
        level = LEVELS[level_key]
        self._tail = level.tail
        self._checksum = checksum
        node = master_node(seed)
        for step in level.prefix:
            node = node.child(step)
        node.compressed()
        self._base = node

    def _node(self, index: int) -> Node:
        node = self._base
        for step in self._tail(index):
            node = node.child(step)
        return node

    def probe(self, index: int) -> str:
        raw = address_hex(self._node(index).key)
        return to_checksum_address("0x" + raw)[2:] if self._checksum else raw

    def reveal(self, index: int) -> Tuple[str, str]:
        key = self._node(index).key
        return to_checksum_address("0x" + address_hex(key)), "0x" + key.hex()


def _is_tty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


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


def prompt_text(label: str, default: str = "") -> str:
    if not _is_tty(sys.stdin):
        return default
    return input(label).strip() or default


def prompt_yes_no(label: str, default: bool = False) -> bool:
    if not _is_tty(sys.stdin):
        return default
    raw = input(f"{label} ({'Y/n' if default else 'y/N'}): ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def prompt_count(label: str, default: int, parser: Callable[[str], int]) -> Tuple[int, bool]:
    if not _is_tty(sys.stdin):
        return default, False
    while True:
        raw = input(f"{label} [{format_count(default)}]: ").strip()
        if not raw:
            return default, False
        try:
            return parser(raw), True
        except ValueError as error:
            print(f"  {error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VanityWallet EVM - vanity address search over a BIP39 seed phrase.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The seed phrase is never accepted as a command-line flag. It is typed at a prompt,\n"
            "piped on stdin, or read from "
            f"{MNEMONIC_ENV}, and never leaves this machine."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")
    path_help = "derivation path style: " + ", ".join(f"{key}={level.label}" for key, level in LEVELS.items())

    search = subparsers.add_parser("search", help="scan derivation indexes for a matching address")
    search.add_argument("--path", choices=list(LEVELS), default=None, help=path_help)
    search.add_argument("--prefix", default=None, help="desired hex prefix, after the 0x")
    search.add_argument("--suffix", default=None, help="desired hex suffix")
    search.add_argument("--case-sensitive", dest="case_sensitive", action="store_true", default=None,
                        help="require an exact EIP-55 checksum case match")
    search.add_argument("--ignore-case", dest="case_sensitive", action="store_false",
                        help="match regardless of case (default)")
    search.add_argument("--start", type=parse_index, default=None, help="first index to scan (e.g. 0, 100k, 5m)")
    search.add_argument("--end", type=parse_index, default=None, help="last index to scan")
    search.add_argument("--limit", type=int, default=None, help="stop after this many matches (0 = unlimited)")
    search.add_argument("--workers", type=int, default=None, help="number of worker processes")
    search.add_argument("--output", default=None, help="append matches to this file")
    search.add_argument("--include-private-keys", action="store_true",
                        help="also write private keys to the output file (dangerous)")
    search.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    lookup = subparsers.add_parser("lookup", help="show the address and private key at a specific index")
    lookup.add_argument("--path", choices=list(LEVELS), default=None, help=path_help)
    lookup.add_argument("--index", type=parse_index, default=None, help="derivation index to reveal")
    lookup.add_argument("--count", type=int, default=1, help="number of consecutive indexes to reveal")

    for sub in (search, lookup):
        sub.add_argument("--passphrase-prompt", action="store_true", help="ask for a BIP39 passphrase")

    parser.add_argument("--list-paths", action="store_true", help="print the supported derivation paths and exit")
    return parser


def resolve_level(chosen: Optional[str]) -> str:
    if chosen is not None:
        return chosen
    return prompt_choice(
        "Select derivation path style:",
        {key: level.label for key, level in LEVELS.items()},
        "No derivation path selected. Pass --path when not running interactively.",
    )


def collect_search_config(args: argparse.Namespace, seed: bytes) -> SearchConfig:
    level_key = resolve_level(args.path)
    level = LEVELS[level_key]
    print(f"Using path: {level.label}")

    prefix = args.prefix if args.prefix is not None else prompt_text("Prefix (blank to skip): ")
    suffix = args.suffix if args.suffix is not None else prompt_text("Suffix (blank to skip): ")
    prefix = clean_pattern(prefix or "")
    suffix = clean_pattern(suffix or "")

    case_sensitive = args.case_sensitive
    if case_sensitive is None:
        case_sensitive = prompt_yes_no("Case sensitive match?", False) if (prefix or suffix) else False

    validate_pattern(prefix, case_sensitive, "Prefix")
    validate_pattern(suffix, case_sensitive, "Suffix")
    pattern = Pattern.create(prefix, suffix, case_sensitive)

    if args.start is not None:
        start, start_given = args.start, True
    else:
        start, start_given = prompt_count("Start index", 0, parse_index)

    default_end = 100_000_000 if pattern.active else 1_000
    if args.end is not None:
        last, end_given = args.end, True
    else:
        last, end_given = prompt_count("End index", max(default_end, start), parse_index)

    if start > last:
        raise SystemExit(f"Start index ({start:,}) must not be greater than the end index ({last:,}).")
    end = last + 1

    if args.limit is not None:
        limit = args.limit
    elif not pattern.active or start_given or end_given:
        limit = 0
    else:
        limit = 1
    if limit < 0:
        raise SystemExit("--limit cannot be negative.")

    workers = args.workers if args.workers is not None else (os.cpu_count() or 1)
    if workers < 1:
        raise SystemExit("--workers must be at least 1.")
    workers = min(workers, max(end - start, 1))

    output = args.output
    if output is None and _is_tty(sys.stdin) and prompt_yes_no("Save matches to a file?", False):
        name = prompt_text("Output file name: ", "matches.txt")
        output = name if os.path.splitext(name)[1] else f"{name}.txt"

    return SearchConfig(
        seed=seed,
        level=level_key,
        label=level.label,
        pattern=pattern,
        start=start,
        end=end,
        limit=limit,
        workers=workers,
        output=output,
        include_private_keys=bool(args.include_private_keys),
    )


def confirm_search(config: SearchConfig, assume_yes: bool) -> bool:
    expected = expected_attempts(config.pattern)
    print("\nSearch plan")
    print(f"  Path            : {config.label}")
    print(f"  Pattern         : {config.pattern.describe()}")
    print(f"  Index range     : {config.start:,} to {config.end - 1:,}")
    print(f"  Workers         : {config.workers}")
    if config.pattern.active:
        print(f"  Expected tries  : ~{format_attempts(expected)} per match")
    if config.output:
        extra = " including private keys" if config.include_private_keys else ""
        print(f"  Output file     : {config.output}{extra}")
    if config.include_private_keys:
        print("\n  WARNING: private keys will be written to disk in plain text.")
    return True


def search_worker(config: SearchConfig, worker_id: int, results: "MPQueue[Message]", stop: MPEvent) -> None:
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        pass

    parent_pid = os.getppid()
    pattern = config.pattern
    fold_case = not pattern.case_sensitive
    matches = pattern.matches
    last_index = config.start - 1
    pending = 0
    since_check = 0
    last_report = time.monotonic()
    try:
        deriver = EvmDeriver(config.seed, config.level, pattern.case_sensitive)
        probe = deriver.probe
        for index in range(config.start + worker_id, config.end, config.workers):
            candidate = probe(index)
            if fold_case:
                candidate = candidate.lower()
            if matches(candidate):
                address, private_key = deriver.reveal(index)
                results.put((HIT, worker_id, index, address, private_key if config.include_private_keys else ""))
            last_index = index
            pending += 1
            since_check += 1
            if since_check >= PROGRESS_CHECK_EVERY:
                since_check = 0
                if stop.is_set() or os.getppid() != parent_pid:
                    break
                now = time.monotonic()
                if now - last_report >= PROGRESS_SECONDS:
                    results.put((PROGRESS, worker_id, pending, last_index))
                    pending = 0
                    last_report = now
    except Exception as error:
        results.put((FAILED, worker_id, f"{type(error).__name__}: {error}"))
    finally:
        results.put((PROGRESS, worker_id, pending, last_index))
        results.put((DONE, worker_id))


def open_output(config: SearchConfig) -> Any:
    handle = open(config.output, "a", encoding="utf-8")
    try:
        os.chmod(config.output, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    columns = f"{'Index':<14}{'Address':<46}"
    if config.include_private_keys:
        columns += "PrivateKey"
    handle.write(
        f"\n# {time.strftime('%Y-%m-%d %H:%M:%S')} | path {config.label} | {config.pattern.describe()}\n"
        f"# {columns.rstrip()}\n"
    )
    handle.flush()
    try:
        os.fsync(handle.fileno())
    except OSError:
        pass
    return handle


def clear_line(active: bool) -> None:
    if active:
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()


def render_progress(checked: int, span: int, hits: int, elapsed: float, active: bool) -> None:
    if not active:
        return
    rate = checked / elapsed if elapsed > 0 else 0.0
    remaining = (span - checked) / rate if rate > 0 else float("inf")
    sys.stderr.write(
        f"\r\033[2K  {checked:,} checked | {rate:,.0f}/s | {hits} hit(s)"
        f" | elapsed {format_duration(elapsed)} | range ETA {format_duration(remaining)}"
    )
    sys.stderr.flush()


def run_search(config: SearchConfig) -> SearchResult:
    context = mp.get_context("spawn")
    results: "MPQueue[Message]" = context.Queue()
    stop: MPEvent = context.Event()
    workers = [
        context.Process(target=search_worker, args=(config, worker_id, results, stop), daemon=True)
        for worker_id in range(config.workers)
    ]

    handle = open_output(config) if config.output else None
    frontier: Dict[int, int] = {worker_id: config.start - 1 for worker_id in range(config.workers)}
    launched: List[Any] = []
    processes_by_id: Dict[int, Any] = {}
    live: set = set()
    hits: List[Tuple[int, str, str]] = []
    failures: List[str] = []
    checked = 0
    span = config.end - config.start
    show_progress = _is_tty(sys.stderr)
    deadline: Optional[float] = None
    idle_since: Optional[float] = None
    interrupted = False
    started = time.monotonic()

    def on_interrupt(_signum: int, _frame: Any) -> None:
        nonlocal interrupted, deadline
        interrupted = True
        stop.set()
        if deadline is None:
            deadline = time.monotonic() + SHUTDOWN_GRACE

    previous_handler: Any = signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGINT, on_interrupt)
    except (ValueError, OSError):
        previous_handler = None

    try:
        try:
            for worker_id, worker in enumerate(workers):
                worker.start()
                launched.append(worker)
                processes_by_id[worker_id] = worker
                live.add(worker_id)
        except Exception as error:
            failures.append(f"could not start worker {len(launched)}: {type(error).__name__}: {error}")
            stop.set()
            deadline = time.monotonic() + SHUTDOWN_GRACE
        while live:
            if deadline is not None and time.monotonic() > deadline:
                break
            try:
                message = results.get(timeout=QUEUE_TIMEOUT)
                idle_since = None
            except queue.Empty:
                now = time.monotonic()
                if idle_since is None:
                    idle_since = now
                elif now - idle_since >= REAP_AFTER_IDLE:
                    idle_since = now
                    for worker_id in sorted(live):
                        process = processes_by_id.get(worker_id)
                        if process is not None and not process.is_alive():
                            live.discard(worker_id)
                            failures.append(
                                f"worker {worker_id} exited without reporting (exit code {process.exitcode})"
                            )
                render_progress(checked, span, len(hits), time.monotonic() - started, show_progress)
                continue

            kind = message[0]
            if kind == PROGRESS:
                _, worker_id, count, last_index = message
                checked += count
                frontier[worker_id] = max(frontier[worker_id], last_index)
            elif kind == HIT:
                if config.limit and len(hits) >= config.limit:
                    continue
                _, _, index, address, private_key = message
                hits.append((index, address, private_key))
                clear_line(show_progress)
                print(f"{index:<14}{address}", flush=True)
                if handle is not None:
                    handle.write(f"{index:<14}{address:<46}{private_key}".rstrip() + "\n")
                    handle.flush()
                    try:
                        os.fsync(handle.fileno())
                    except OSError:
                        pass
                if config.limit and len(hits) >= config.limit:
                    stop.set()
                    if deadline is None:
                        deadline = time.monotonic() + SHUTDOWN_GRACE
            elif kind == FAILED:
                failures.append(f"worker {message[1]}: {message[2]}")
                stop.set()
                if deadline is None:
                    deadline = time.monotonic() + SHUTDOWN_GRACE
            elif kind == DONE:
                live.discard(message[1])
            render_progress(checked, span, len(hits), time.monotonic() - started, show_progress)
    finally:
        elapsed = time.monotonic() - started
        stop.set()
        if previous_handler is not None:
            try:
                signal.signal(signal.SIGINT, previous_handler)
            except (ValueError, OSError):
                pass
        for worker in launched:
            worker.join(timeout=JOIN_TIMEOUT)
        for worker in launched:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=JOIN_TIMEOUT)
        try:
            results.cancel_join_thread()
            results.close()
        except Exception:
            pass
        if handle is not None:
            handle.close()
        clear_line(show_progress)

    covered = checked >= config.end - config.start
    resume = config.end if covered else (min(frontier.values()) + 1 if frontier else config.start)
    return SearchResult(
        hits=hits,
        checked=checked,
        elapsed=elapsed,
        resume_index=min(max(resume, config.start), config.end),
        interrupted=interrupted,
        failures=failures,
    )


def report_search(config: SearchConfig, result: SearchResult) -> None:
    rate = result.checked / result.elapsed if result.elapsed > 0 else 0.0
    print("\nSummary")
    print(f"  Checked   : {result.checked:,} addresses in {format_duration(result.elapsed)} ({rate:,.0f}/s)")
    print(f"  Matches   : {len(result.hits)}")
    if result.failures:
        print("  Failures  :")
        for failure in result.failures:
            print(f"    {failure}")
    if config.output and result.hits:
        print(f"  Saved to  : {config.output}")
    if (result.interrupted or result.failures) and result.resume_index < config.end:
        print(f"  Resume from index : {result.resume_index:,}")
    if result.hits and not config.include_private_keys:
        print("\nTo see the private key, run the tool again, choose \"Private key lookup\",")
        print(f"pick the same derivation path, and enter index {min(hit[0] for hit in result.hits):,}.")


def run_lookup(args: argparse.Namespace, seed: bytes) -> None:
    level_key = resolve_level(args.path)
    level = LEVELS[level_key]
    index = args.index if args.index is not None else prompt_count("Index", 0, parse_index)[0]
    count = max(1, args.count)
    if index + count - 1 > MAX_INDEX:
        raise SystemExit(f"Index range exceeds the BIP32 maximum of {MAX_INDEX}.")

    deriver = EvmDeriver(seed, level_key, True)
    print("\nPrivate keys grant full control of these accounts. Keep them off screen shares and clipboards.")
    for offset in range(count):
        current = index + offset
        address, private_key = deriver.reveal(current)
        print(f"\nIndex       : {current}")
        print(f"Path        : {format_path(level.label, current)}")
        print(f"Address     : {address}")
        print(f"Private Key : {private_key}")


def backend_name() -> str:
    try:
        return type(keys.backend).__name__
    except Exception:
        return "unknown"


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_paths:
        print("Supported derivation paths:")
        for key, level in LEVELS.items():
            print(f"  {key:<10} {level.label}")
        return 0

    command = args.command
    if command is None:
        command = prompt_choice(
            "What would you like to do?",
            {"search": "Vanity address search", "lookup": "Private key lookup"},
            "No action selected. Pass 'search' or 'lookup' when not running interactively.",
        )
        args = parser.parse_args([command])

    if backend_name() == "NativeECCBackend":
        print("Note: eth-keys is using its pure-Python backend. Install coincurve for a large speedup.",
              file=sys.stderr)

    mnemonic = read_mnemonic()
    passphrase = read_passphrase(args.passphrase_prompt)
    seed = load_seed(mnemonic, passphrase)

    if command == "lookup":
        run_lookup(args, seed)
        return 0

    config = collect_search_config(args, seed)
    if not confirm_search(config, args.yes):
        print("Cancelled.")
        return 1

    print(f"\n{'Index':<14}Address")
    result = run_search(config)
    report_search(config, result)
    return 0 if result.hits or not config.pattern.active else 1


if __name__ == "__main__":
    raise SystemExit(main())
