"""Hash identifier / computer / cracker.

REST  POST /hash/identify   body { "hash": "..." } → list of candidate algorithms
REST  POST /hash/compute    body { "plaintext": "...", "algorithm": "sha256" }
REST  POST /hash/crack      body { "hash": "...", "algorithm": "auto"|"<name>",
                                   "wordlist"?: ["..."], "use_builtin"?: true }
WS    /ws/hash-crack        same payload, streams progress

Fast hashes via hashlib. Slow hashes (bcrypt / scrypt / argon2 / unix crypt /
mysql) via passlib if available — gracefully degrade if not.

Note: this only cracks via dictionary/wordlist. No brute force. The intent is
to flag obviously-weak passwords (`password`, `123456`, etc.) on hashes you
own, not to break strong hashes.
"""
from __future__ import annotations

import asyncio
import gzip
import hashlib
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterator

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from lib import scope
from lib.errors import ErrorCode, ws_error
from lib.mode import get_engagement_id, get_mode

logger = logging.getLogger(__name__)

router = APIRouter(tags=["hash"])

# Hashes/plaintexts/wordlist items are bounded so a runaway client can't push
# multi-megabyte strings through pydantic. Hashes max out at ~256 chars even
# for the largest schemes (argon2 ~96, sha512 hex = 128).
MAX_HASH_LEN = 512
MAX_PLAINTEXT_LEN = 4096
MAX_WORDLIST_ITEM_LEN = 1024
MAX_WORDLIST_ITEMS = 200_000
MAX_ALGORITHM_LEN = 64


# ── External wordlists ────────────────────────────────────────────────────────

def _wordlists_dir() -> Path:
    """Find the wordlists directory in both dev and PyInstaller-bundled runs."""
    # PyInstaller extracts data files to sys._MEIPASS at runtime
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        p = Path(meipass) / "wordlists"
        if p.exists():
            return p
    # Dev: next to this router file's parent (the backend dir)
    here = Path(__file__).resolve()
    return here.parent.parent / "wordlists"


ROCKYOU_PATH = _wordlists_dir() / "rockyou.txt.gz"
ROCKYOU_LINES_APPROX = 14_344_391   # used for progress; exact count loaded lazily


def _rockyou_available() -> dict[str, Any]:
    if not ROCKYOU_PATH.exists():
        return {"available": False, "path": str(ROCKYOU_PATH)}
    return {
        "available": True,
        "path": str(ROCKYOU_PATH),
        "size_bytes": ROCKYOU_PATH.stat().st_size,
        "approx_lines": ROCKYOU_LINES_APPROX,
    }


def _iter_rockyou() -> Iterator[str]:
    """Stream rockyou.txt.gz one line at a time. ~14.3M passwords."""
    if not ROCKYOU_PATH.exists():
        return
    with gzip.open(ROCKYOU_PATH, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\r\n")


# ── Algorithm registry ────────────────────────────────────────────────────────

# Fast hashes — all available via Python's hashlib
HASHLIB_FAST = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2b", "blake2s",
]

# ── Pure-Python MD4 (modern OpenSSL disables MD4, so hashlib can't do it) ────

def _md4(data: bytes) -> bytes:
    """Pure-Python MD4. Reference: RFC 1320.

    We need this because modern OpenSSL 3 disables MD4 in `hashlib.new('md4',
    ...)`, but NTLM requires it (NTLM = MD4(UTF-16-LE(password))).
    """
    import struct

    def rol(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    def F(x, y, z): return (x & y) | (~x & 0xFFFFFFFF & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z

    # Padding: append 0x80, then zeros, then 64-bit length, to make len % 64 == 0
    mlen = len(data)
    pad_count = (55 - mlen) % 64
    data = data + b"\x80" + b"\x00" * pad_count + struct.pack("<Q", mlen * 8)

    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    # Round 1 indexes: word, shift
    r1 = [(0, 3), (1, 7), (2, 11), (3, 19), (4, 3), (5, 7), (6, 11), (7, 19),
          (8, 3), (9, 7), (10, 11), (11, 19), (12, 3), (13, 7), (14, 11), (15, 19)]
    # Round 2 — column-major reads
    r2 = [(0, 3), (4, 5), (8, 9), (12, 13), (1, 3), (5, 5), (9, 9), (13, 13),
          (2, 3), (6, 5), (10, 9), (14, 13), (3, 3), (7, 5), (11, 9), (15, 13)]
    # Round 3 — special order
    r3 = [(0, 3), (8, 9), (4, 11), (12, 15), (2, 3), (10, 9), (6, 11), (14, 15),
          (1, 3), (9, 9), (5, 11), (13, 15), (3, 3), (11, 9), (7, 11), (15, 15)]

    for i in range(0, len(data), 64):
        X = list(struct.unpack("<16I", data[i:i + 64]))
        A, B, C, D = state
        for (k, s) in r1:
            A = rol((A + F(B, C, D) + X[k]) & 0xFFFFFFFF, s)
            A, B, C, D = D, A, B, C
        for (k, s) in r2:
            A = rol((A + G(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            A, B, C, D = D, A, B, C
        for (k, s) in r3:
            A = rol((A + H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            A, B, C, D = D, A, B, C
        state = [(state[j] + v) & 0xFFFFFFFF for j, v in enumerate((A, B, C, D))]

    return struct.pack("<4I", *state)


# Slow hashes — use bcrypt + argon2 packages directly, and passlib for the rest.
# bcrypt 5.0+ broke passlib 1.7.4 compatibility, so we shim around it.

class _BcryptAdapter:
    """passlib-compatible wrapper around the `bcrypt` package."""

    @staticmethod
    def hash(password: str) -> str:
        import bcrypt as _b
        pw = password.encode("utf-8")[:72]   # bcrypt truncates >72 bytes
        return _b.hashpw(pw, _b.gensalt()).decode("utf-8")

    @staticmethod
    def verify(password: str, hash_str: str) -> bool:
        import bcrypt as _b
        pw = password.encode("utf-8")[:72]
        try:
            return _b.checkpw(pw, hash_str.encode("utf-8"))
        except (ValueError, TypeError):
            return False


class _Argon2Adapter:
    """passlib-compatible wrapper around argon2-cffi."""

    @staticmethod
    def hash(password: str) -> str:
        from argon2 import PasswordHasher
        return PasswordHasher().hash(password)

    @staticmethod
    def verify(password: str, hash_str: str) -> bool:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError, InvalidHashError
        try:
            return PasswordHasher().verify(hash_str, password)
        except (VerifyMismatchError, InvalidHashError, Exception):
            return False


SLOW_HASHES: dict[str, Any] = {}
try:
    SLOW_HASHES["bcrypt"] = _BcryptAdapter
except Exception:
    pass
try:
    SLOW_HASHES["argon2"] = _Argon2Adapter
except Exception:
    pass

# Everything else via passlib (these work fine with passlib 1.7.4)
try:
    from passlib.hash import (
        sha256_crypt as _sha256_crypt,
        sha512_crypt as _sha512_crypt,
        md5_crypt as _md5_crypt,
        mysql41 as _mysql41,
        mysql323 as _mysql323,
        lmhash as _lmhash,
    )
    SLOW_HASHES.update({
        "sha256_crypt":  _sha256_crypt,   # Unix $5$
        "sha512_crypt":  _sha512_crypt,   # Unix $6$
        "md5_crypt":     _md5_crypt,      # Unix $1$
        "mysql41":       _mysql41,
        "mysql323":      _mysql323,
        "lm":            _lmhash,
    })
except ImportError:
    pass


# NTLM — md4 of UTF-16-LE password. Uses our pure-Python MD4 since modern
# OpenSSL 3 disables MD4 in hashlib.
def _ntlm(password: str) -> str:
    return _md4(password.encode("utf-16-le")).hex()


CUSTOM_HASHES = {"ntlm"}
ALL_ALGORITHMS = sorted(set(HASHLIB_FAST) | CUSTOM_HASHES | set(SLOW_HASHES.keys()))


# ── Hash signatures for identification ────────────────────────────────────────

# Each entry: (regex, list of candidate algorithm names)
SIGNATURES: list[tuple[str, list[str]]] = [
    # Length-based (hex) — only candidates that can validate from a bare-hex
    # form. Salt-prefixed schemes like md5_crypt ($1$), sha256_crypt ($5$),
    # mysql41 (*…) etc. have their own dedicated patterns below.
    (r"^aad3b435b51404eeaad3b435b51404ee$", ["lm (empty password marker)"]),
    (r"^[a-fA-F0-9]{32}$",  ["md5", "ntlm"]),
    (r"^[a-fA-F0-9]{40}$",  ["sha1"]),
    (r"^[a-fA-F0-9]{56}$",  ["sha224", "sha3_224"]),
    (r"^[a-fA-F0-9]{64}$",  ["sha256", "sha3_256", "blake2s"]),
    (r"^[a-fA-F0-9]{96}$",  ["sha384", "sha3_384"]),
    (r"^[a-fA-F0-9]{128}$", ["sha512", "sha3_512", "blake2b"]),

    # Prefixed schemes — these are unambiguous
    (r"^\$2[abxy]\$\d+\$",   ["bcrypt"]),
    (r"^\$1\$",              ["md5_crypt"]),
    (r"^\$5\$",              ["sha256_crypt"]),
    (r"^\$6\$",              ["sha512_crypt"]),
    (r"^\$argon2(i|d|id)\$", ["argon2"]),
    (r"^\$y\$",              ["yescrypt (not supported)"]),
    (r"^\*[A-F0-9]{40}$",    ["mysql41"]),   # MySQL hashes start with *
    (r"^[a-fA-F0-9]{16}$",   ["mysql323"]),
]


def _identify(h: str) -> list[str]:
    candidates: list[str] = []
    for pattern, names in SIGNATURES:
        if re.match(pattern, h):
            for n in names:
                if n not in candidates:
                    candidates.append(n)
    return candidates


# ── Compute ───────────────────────────────────────────────────────────────────

def compute(algorithm: str, plaintext: str) -> str:
    algorithm = algorithm.lower()
    if algorithm == "ntlm":
        return _ntlm(plaintext)
    if algorithm in HASHLIB_FAST:
        h = hashlib.new(algorithm)
        h.update(plaintext.encode("utf-8"))
        return h.hexdigest()
    if algorithm in SLOW_HASHES:
        return SLOW_HASHES[algorithm].hash(plaintext)
    raise ValueError(f"unknown or unavailable algorithm: {algorithm}")


# ── Crack ─────────────────────────────────────────────────────────────────────

def make_verifier(algorithm: str, target: str) -> Callable[[str], bool]:
    """Return a function that takes a candidate plaintext and reports if it matches."""
    algorithm = algorithm.lower()
    target_lower = target.lower()

    if algorithm == "ntlm":
        def _check(pw: str) -> bool:
            return _ntlm(pw).lower() == target_lower
        return _check

    if algorithm in HASHLIB_FAST:
        def _check_fast(pw: str) -> bool:
            h = hashlib.new(algorithm)
            h.update(pw.encode("utf-8"))
            return h.hexdigest().lower() == target_lower
        return _check_fast

    if algorithm in SLOW_HASHES:
        handler = SLOW_HASHES[algorithm]
        def _check_slow(pw: str) -> bool:
            try:
                return handler.verify(pw, target)
            except (ValueError, TypeError):
                return False
        return _check_slow

    raise ValueError(f"unknown or unavailable algorithm: {algorithm}")


# Mini built-in wordlist of common passwords. ~500 entries.
COMMON_PASSWORDS: list[str] = [
    "", "password", "123456", "12345678", "12345", "1234567890", "1234567",
    "qwerty", "abc123", "password1", "111111", "iloveyou", "1234", "1q2w3e4r",
    "admin", "welcome", "monkey", "login", "dragon", "passw0rd", "master",
    "hello", "freedom", "whatever", "qazwsx", "trustno1", "letmein", "starwars",
    "P@ssw0rd", "Password1", "p@ssword", "qwerty123", "1qaz2wsx", "qwertyuiop",
    "shadow", "michael", "jennifer", "jordan", "superman", "harley", "ranger",
    "asshole", "fuckyou", "buster", "thomas", "tigger", "robert", "soccer",
    "batman", "test", "pass", "killer", "hockey", "george", "charlie", "andrew",
    "michelle", "love", "sunshine", "jessica", "asdf", "Maggie", "121212",
    "biteme", "matrix", "purple", "amanda", "summer", "michael1", "secret",
    "andrea", "carlos", "elizabeth", "patrick", "internet", "scooter", "orange",
    "11111", "golfer", "cookie", "richard", "samantha", "bigdog", "guitar",
    "jackson", "whatever", "mickey", "chicken", "sparky", "snoopy", "maverick",
    "phoenix", "camaro", "sexy", "peanut", "morgan", "welcome1", "alexander",
    "yankees", "111222", "bigboss", "champ", "joshua", "compaq", "fishing",
    "asdfgh", "diamond", "rachel", "ginger", "dakota", "anthony", "yamaha",
    "justin", "ginger", "nicholas", "blowme", "cheese", "matthew", "121212",
    "p@ssw0rd!", "Pa$$word", "Welcome123", "Spring2024", "Summer2024", "Winter2024",
    "Spring2025", "Summer2025", "Winter2025", "Spring2026", "Summer2026",
    "Changeme", "changeme", "default", "guest", "root", "rootroot",
    "toor", "Sysadmin", "service", "service123", "operator", "manager",
    "supervisor", "demo", "test123", "trial", "abcdef", "abcdef123",
    "qwerty1", "qwerty12", "qwerty123", "Qwerty1!", "Qwerty123!",
    "asdfgh", "asdfghjkl", "zxcvbnm", "zxcvbn", "zxcvbnm123",
    "iloveu", "iloveme", "trust", "ninja", "azerty", "thunder",
    "killer1", "internet1", "computer", "computer1", "mustang",
    "qwer1234", "qwer123456", "asdf1234", "1q2w3e", "1q2w3e4r5t",
    "letmein1", "letmein!", "P@$$w0rd", "Password!", "Password1!",
    "Welcome1", "Welcome2", "Welcome!", "Welcome@", "Welcome123!",
    "Admin@123", "admin@123", "admin123", "Admin123", "administrator",
    "Administrator", "P@ssword1", "P@ssword2", "P@ssword!", "P@ssword@",
    "spring", "summer", "autumn", "winter", "Spring1", "Summer1",
    "Football1", "Baseball1", "footballl", "basketball", "soccer1",
    "google", "facebook", "twitter", "amazon", "apple", "Microsoft1",
    "linkedin", "instagram", "Snapchat1", "tiktok",
    "abc", "abcd", "abcde", "1", "0", "00000", "00000000",
    "11", "1111", "11111", "1111111", "11111111",
    "22", "222", "2222", "22222", "2222222", "22222222",
    "99", "999", "9999", "99999", "9999999", "99999999",
    "8888", "88888", "888888", "8888888", "88888888",
    "654321", "7654321", "87654321", "987654321", "0987654321",
    "abcdefgh", "abcdefghij", "Aa123456", "Aa12345!", "Aa12345@",
    "Passw0rd!", "Passw0rd@", "Passw0rd#", "Password@123",
    "iloveyou1", "iloveyou2", "iloveyou3", "ilovegod", "ilove",
    "shadow1", "shadow123", "shadow!", "shadow@",
    # Vendor / device defaults
    "ubnt", "raspberry", "raspberrypi", "pi", "nasa", "Cisco", "cisco",
    "linksys", "netgear", "tplink", "huawei", "zte", "asus", "dlink",
    "1234567a", "12345678a", "Admin#1", "Admin1!", "admin1!",
    # Common keyboard walks
    "qweasd", "qweasdzxc", "qweasdzxc123", "1qazxsw2", "1qaz!QAZ",
    "zaq12wsx", "1q2w3e!", "!QAZxsw2", "1qaz@WSX",
    "azertyuiop", "wxcvbn", "azerty123",
    # Names
    "jacob", "emma", "olivia", "noah", "ava", "isabella", "sophia",
    "mia", "charlotte", "amelia", "evelyn", "abigail",
    "alex", "alexis", "ashley", "amber", "amy", "bailey", "becky",
    "ben", "benji", "brad", "brandon", "brittany", "brooke", "bruce",
    "cameron", "candice", "casey", "chris", "christian", "claire", "cody",
    "daniel", "danielle", "david", "dennis", "diana", "diego", "donald",
    "edward", "elaine", "eric", "evan", "fred", "frank",
    "gary", "gavin", "gina", "grace", "greg", "hailey", "hanna",
    "ian", "isaac", "jack", "jacob", "jake", "james", "jane", "jasmine",
    "jason", "jay", "jeff", "jeffery", "jerry", "jim", "jodi", "joel",
    "john", "jonny", "joseph", "joshua", "julia", "julie", "justin",
    "karl", "kate", "katherine", "kathy", "katie", "kayla", "keith",
    "kenny", "kevin", "kim", "kimberly", "kris", "kristin", "kyle",
    "larry", "laura", "lauren", "lee", "leo", "linda", "lisa", "liz",
    "louis", "louisa", "lucia", "lucy", "luis", "luke", "lynn",
    "maria", "mark", "marcus", "martin", "mary", "matt", "max",
    "megan", "melissa", "melinda", "michael", "michelle", "mike",
    "molly", "monica", "mr", "mrs",
    "nathan", "neil", "nina", "noel", "nora",
    "oliver", "owen", "patricia", "paul", "peter", "philip", "phyllis",
    "rachel", "rebecca", "rich", "richard", "robert", "roger", "ron",
    "ronald", "rose", "ruth", "ryan",
    "sam", "samantha", "samuel", "sandra", "sara", "sarah", "scott",
    "sean", "seth", "sharon", "sheila", "shelby", "shirley", "simon",
    "stacy", "stanley", "stephanie", "stephen", "steve", "steven",
    "susan", "tammy", "tara", "ted", "terri", "terry", "thomas",
    "tim", "timothy", "tina", "todd", "tom", "tommy", "tony",
    "tracy", "travis", "trent", "tyler", "vance", "vanessa", "vera",
    "vicki", "victor", "victoria", "vincent", "vivian", "wade", "walter",
    "wayne", "wendy", "william", "yvonne", "zachary", "zane", "zoe",
]
# Dedupe + trim
COMMON_PASSWORDS = list(dict.fromkeys(COMMON_PASSWORDS))


# ── REST endpoints ────────────────────────────────────────────────────────────

class IdentifyRequest(BaseModel):
    hash: str = Field(..., max_length=MAX_HASH_LEN)


class ComputeRequest(BaseModel):
    plaintext: str = Field(..., max_length=MAX_PLAINTEXT_LEN)
    algorithm: str = Field(..., max_length=MAX_ALGORITHM_LEN)


class CrackRequest(BaseModel):
    hash: str = Field(..., max_length=MAX_HASH_LEN)
    algorithm: str = Field("auto", max_length=MAX_ALGORITHM_LEN)
    wordlist: list[str] = Field(default_factory=list, max_length=MAX_WORDLIST_ITEMS)
    use_builtin: bool = True
    use_rockyou: bool = False
    max_candidates: int = Field(100000, ge=1, le=200_000_000)


@router.get("/hash/algorithms")
def list_algorithms() -> dict[str, Any]:
    """Enumerate supported algorithms, grouped by speed tier, + wordlist status."""
    return {
        "fast": sorted(HASHLIB_FAST + ["ntlm"]),
        "slow": sorted(SLOW_HASHES.keys()),
        "rockyou": _rockyou_available(),
    }


@router.post("/hash/identify")
def identify_hash(req: IdentifyRequest) -> dict[str, Any]:
    h = req.hash.strip()
    if not h:
        raise HTTPException(status_code=400, detail="hash is required")
    candidates = _identify(h)
    return {"hash": h, "length": len(h), "candidates": candidates}


@router.post("/hash/compute")
def compute_hash(req: ComputeRequest) -> dict[str, Any]:
    try:
        result = compute(req.algorithm, req.plaintext)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"algorithm": req.algorithm.lower(), "hash": result,
            "input_length": len(req.plaintext)}


def _candidate_algorithms(hash_str: str, requested: str) -> list[str]:
    """For 'auto', return ALL identified candidates we can handle (32-hex
    hashes are ambiguous between md5 and ntlm — try both). Otherwise return
    just the requested algorithm.
    """
    if requested.lower() != "auto":
        return [requested.lower()]
    out: list[str] = []
    for cand in _identify(hash_str):
        bare = cand.split("(")[0].strip()
        if (bare in HASHLIB_FAST or bare in SLOW_HASHES or bare == "ntlm") and bare not in out:
            out.append(bare)
    if not out:
        raise HTTPException(
            status_code=400,
            detail=f"could not identify algorithm. Identify the hash first and pick manually.",
        )
    return out


def _check_rockyou_compatible(algos: list[str]) -> None:
    """rockyou + slow hash = days of crunching for nothing useful. Hard refuse."""
    slow_in_use = [a for a in algos if a in SLOW_HASHES]
    if slow_in_use:
        raise HTTPException(
            status_code=400,
            detail=(
                f"rockyou disabled for slow algorithms ({', '.join(slow_in_use)}) — "
                "each attempt is ~0.1-0.4s so 14M entries ≈ weeks of CPU. "
                "Use a smaller targeted wordlist for slow hashes."
            ),
        )


@router.post("/hash/crack")
def crack(req: CrackRequest, request: Request) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    h = req.hash.strip()
    if not h:
        raise HTTPException(status_code=400, detail="hash is required")
    algos = _candidate_algorithms(h, req.algorithm)
    if req.use_rockyou:
        _check_rockyou_compatible(algos)
        if not ROCKYOU_PATH.exists():
            raise HTTPException(status_code=400,
                                detail=f"rockyou.txt.gz not found at {ROCKYOU_PATH}")

    # Pre-collect the "small" portion (common + user wordlist) so we can dedupe
    # without holding rockyou in memory.
    small_candidates: list[str] = []
    if req.use_builtin:
        small_candidates.extend(COMMON_PASSWORDS)
    small_candidates.extend(req.wordlist)
    small_candidates = list(dict.fromkeys(small_candidates))[: req.max_candidates]

    def stream_candidates() -> Iterator[str]:
        seen: set[str] = set()
        for c in small_candidates:
            if c not in seen:
                seen.add(c); yield c
        if req.use_rockyou:
            for c in _iter_rockyou():
                if c not in seen:
                    seen.add(c); yield c

    t0 = time.monotonic()
    found: str | None = None
    matched_algorithm: str | None = None
    tried_total = 0

    for algo in algos:
        try:
            check = make_verifier(algo, h)
        except ValueError:
            continue
        tried_this = 0
        for cand in stream_candidates():
            tried_this += 1
            try:
                if check(cand):
                    found = cand
                    matched_algorithm = algo
                    break
            except Exception:
                continue
            if req.max_candidates and tried_this >= req.max_candidates:
                break
        tried_total += tried_this
        if found is not None:
            break

    elapsed = round(time.monotonic() - t0, 3)
    total_estimate = len(small_candidates) + (ROCKYOU_LINES_APPROX if req.use_rockyou else 0)
    return {
        "hash": h,
        "algorithm": matched_algorithm or algos[0],
        "algorithms_tried": algos,
        "tried": tried_total,
        "total_candidates": total_estimate,
        "elapsed_seconds": elapsed,
        "cracked": found is not None,
        "plaintext": found if found is not None else None,
    }


# ── WS streaming endpoint ─────────────────────────────────────────────────────

@router.websocket("/ws/hash-crack")
async def hash_crack_ws(ws: WebSocket) -> None:
    await ws.accept()
    stop = asyncio.Event()

    async def listen_for_stop() -> None:
        try:
            while True:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("action") == "stop":
                    stop.set(); return
        except WebSocketDisconnect:
            stop.set()
        except Exception:
            stop.set()

    try:
        init = await ws.receive_json()

        # Offline cracking is still an attributable evidence-producing action.
        engagement_id = init.get("engagement_id") or get_engagement_id(ws)
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        if not await scope.enforce_engagement_present_ws(ws, engagement_id, mode):
            stop.set()
            return

        h = str(init.get("hash", "")).strip()
        algorithm = str(init.get("algorithm", "auto")).lower()[:MAX_ALGORITHM_LEN]
        use_builtin = bool(init.get("use_builtin", True))
        use_rockyou = bool(init.get("use_rockyou", False))
        wordlist_raw = init.get("wordlist", []) or []
        if not isinstance(wordlist_raw, list):
            wordlist_raw = []
        # Cap wordlist size + per-item length so a hostile client can't OOM us.
        wordlist = [
            str(w)[:MAX_WORDLIST_ITEM_LEN]
            for w in wordlist_raw[:MAX_WORDLIST_ITEMS]
            if isinstance(w, (str, int, float))
        ]
        try:
            max_candidates = int(init.get("max_candidates", 50_000_000))
        except (TypeError, ValueError):
            max_candidates = 50_000_000
        max_candidates = max(1, min(max_candidates, 200_000_000))

        if not h:
            await ws.send_json(ws_error(ErrorCode.BAD_REQUEST, "hash is required"))
            await ws.close(); return
        if len(h) > MAX_HASH_LEN:
            await ws.send_json(ws_error(
                ErrorCode.PAYLOAD_TOO_LARGE,
                f"hash is too long (max {MAX_HASH_LEN} chars)",
            ))
            await ws.close(); return

        try:
            algos = _candidate_algorithms(h, algorithm)
            if use_rockyou:
                _check_rockyou_compatible(algos)
                if not ROCKYOU_PATH.exists():
                    raise HTTPException(status_code=400,
                                        detail=f"rockyou.txt.gz not found at {ROCKYOU_PATH}")
        except HTTPException as exc:
            await ws.send_json(ws_error(ErrorCode.BAD_REQUEST, str(exc.detail)))
            await ws.close(); return

        small_candidates: list[str] = []
        if use_builtin:
            small_candidates.extend(COMMON_PASSWORDS)
        small_candidates.extend(wordlist)
        small_candidates = list(dict.fromkeys(small_candidates))

        per_algo_total = len(small_candidates) + (ROCKYOU_LINES_APPROX if use_rockyou else 0)
        total_with_algos = per_algo_total * len(algos)

        await ws.send_json({"type": "started",
                            "algorithm": "+".join(algos),
                            "total": total_with_algos,
                            "builtin_used": use_builtin,
                            "rockyou_used": use_rockyou})

        listener = asyncio.create_task(listen_for_stop())
        try:
            t0 = time.monotonic()
            last_progress = 0.0
            found: str | None = None
            matched_algo: str | None = None
            tried = 0

            for algo in algos:
                if stop.is_set() or found is not None:
                    break
                try:
                    check = make_verifier(algo, h)
                except ValueError:
                    continue
                is_slow = algo in SLOW_HASHES
                chunk_size = 16 if is_slow else 5000

                def _try_chunk(chunk: list[str]) -> tuple[str | None, int]:
                    hits: str | None = None
                    count = 0
                    for cand in chunk:
                        count += 1
                        try:
                            if check(cand):
                                hits = cand
                                break
                        except Exception:
                            continue
                    return hits, count

                # Iterator that chains small_candidates → rockyou into the same loop
                def stream() -> Iterator[str]:
                    seen: set[str] = set()
                    for c in small_candidates:
                        if c not in seen:
                            seen.add(c); yield c
                    if use_rockyou:
                        for c in _iter_rockyou():
                            if c not in seen:
                                seen.add(c); yield c

                buf: list[str] = []
                for cand in stream():
                    if stop.is_set():
                        break
                    if tried >= max_candidates:
                        break
                    buf.append(cand)
                    if len(buf) >= chunk_size:
                        hit, count = await asyncio.to_thread(_try_chunk, buf)
                        buf = []
                        tried += count
                        if hit is not None:
                            found = hit; matched_algo = algo; break
                        now = time.monotonic()
                        if now - last_progress > 0.2:
                            last_progress = now
                            await ws.send_json({
                                "type": "progress", "tried": tried,
                                "total": total_with_algos,
                                "elapsed": round(now - t0, 2),
                            })
                # flush trailing buffer
                if not stop.is_set() and found is None and buf:
                    hit, count = await asyncio.to_thread(_try_chunk, buf)
                    tried += count
                    if hit is not None:
                        found = hit; matched_algo = algo

            elapsed = round(time.monotonic() - t0, 3)
            await ws.send_json({
                "type": "done",
                "cracked": found is not None,
                "plaintext": found,
                "algorithm": matched_algo or algos[0],
                "tried": tried, "total": total_with_algos,
                "elapsed_seconds": elapsed,
                "stopped": stop.is_set() and found is None,
            })
        finally:
            listener.cancel()
    except WebSocketDisconnect:
        stop.set()
    except Exception as exc:
        logger.exception("hash crack ws failed")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                f"Hash crack failed ({type(exc).__name__})",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
