"""Steganography — hide, extract, and detect data in images and audio.

REST  POST /stego/capacity              multipart: file → capacity report
REST  POST /stego/embed                 multipart: carrier + payload → stego file
REST  POST /stego/extract               multipart: file [+ password] → recovered payload
REST  POST /stego/analyze               multipart: file → chi-square + appended + EXIF
REST  POST /stego/strip-metadata        multipart: image → cleaned image bytes
REST  GET  /stego/info                  static format/algorithm reference

Carriers:
  PNG / BMP — full LSB embed + extract (uses RGB channels, preserves alpha).
  WAV       — full LSB embed + extract in PCM samples (any width).
  JPEG      — extract / analyze only (lossy; can't reliably LSB-embed).

Payload container (binary, prepended to the LSB bitstream):
  6 bytes  magic           "NTSTEG"
  1 byte   version         0x01
  1 byte   flags           bit0=encrypted (AES-GCM), bit1=compressed (zlib),
                           bit2=has_filename
  4 bytes  payload_len     length of trailing payload bytes, big-endian uint32
  [1 byte  filename_len   ] only if has_filename
  [N bytes filename       ] only if has_filename, UTF-8
  [16 bytes salt          ] only if encrypted
  [12 bytes nonce         ] only if encrypted
  N bytes  payload         ciphertext (+16-byte GCM tag) if encrypted, else
                           compressed-or-raw bytes
"""
from __future__ import annotations

import base64
import io
import math
import os
import struct
import wave
import zlib
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Request, Response, UploadFile

from PIL import Image, ExifTags

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from lib import scope
from lib.mode import get_engagement_id, get_mode

router = APIRouter(tags=["stego"])


# ── Container format ──────────────────────────────────────────────────────────

MAGIC = b"NTSTEG"
VERSION = 0x01
FLAG_ENCRYPTED = 0x01
FLAG_COMPRESSED = 0x02
FLAG_HAS_FILENAME = 0x04

HEADER_FIXED = len(MAGIC) + 1 + 1 + 4   # magic + version + flags + payload_len = 12

# Scrypt params — moderate cost, fine for interactive use
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LEN = 32
SCRYPT_SALT_LEN = 16
AESGCM_NONCE_LEN = 12
AESGCM_TAG_LEN = 16


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=SCRYPT_KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def build_container(
    payload: bytes,
    *,
    password: str | None,
    compress: bool,
    filename: str | None,
) -> bytes:
    """Wrap raw payload bytes in the NTSTEG container."""
    flags = 0
    body = payload
    if compress:
        compressed = zlib.compress(body, 9)
        if len(compressed) < len(body):
            body = compressed
            flags |= FLAG_COMPRESSED

    extras = b""
    if filename:
        fn = filename.encode("utf-8")[:255]
        flags |= FLAG_HAS_FILENAME
        extras += bytes([len(fn)]) + fn

    if password:
        salt = os.urandom(SCRYPT_SALT_LEN)
        nonce = os.urandom(AESGCM_NONCE_LEN)
        key = _derive_key(password, salt)
        body = AESGCM(key).encrypt(nonce, body, None)
        extras += salt + nonce
        flags |= FLAG_ENCRYPTED

    header = MAGIC + bytes([VERSION, flags]) + struct.pack(">I", len(body))
    return header + extras + body


def parse_container(blob: bytes, *, password: str | None) -> dict[str, Any]:
    """Parse a NTSTEG container from raw bytes. Returns plaintext + metadata."""
    if len(blob) < HEADER_FIXED or not blob.startswith(MAGIC):
        raise ValueError("no NTSTEG magic header found")
    pos = len(MAGIC)
    version = blob[pos]; pos += 1
    if version != VERSION:
        raise ValueError(f"unsupported container version {version}")
    flags = blob[pos]; pos += 1
    payload_len = struct.unpack(">I", blob[pos : pos + 4])[0]; pos += 4

    filename: str | None = None
    if flags & FLAG_HAS_FILENAME:
        if pos >= len(blob):
            raise ValueError("truncated container (filename header)")
        fn_len = blob[pos]; pos += 1
        if pos + fn_len > len(blob):
            raise ValueError("truncated container (filename body)")
        filename = blob[pos : pos + fn_len].decode("utf-8", errors="replace")
        pos += fn_len

    salt = nonce = b""
    if flags & FLAG_ENCRYPTED:
        if pos + SCRYPT_SALT_LEN + AESGCM_NONCE_LEN > len(blob):
            raise ValueError("truncated container (crypto headers)")
        salt = blob[pos : pos + SCRYPT_SALT_LEN]; pos += SCRYPT_SALT_LEN
        nonce = blob[pos : pos + AESGCM_NONCE_LEN]; pos += AESGCM_NONCE_LEN

    if pos + payload_len > len(blob):
        raise ValueError(
            f"truncated payload (need {payload_len} bytes, have {len(blob) - pos})"
        )
    body = blob[pos : pos + payload_len]

    if flags & FLAG_ENCRYPTED:
        if not password:
            raise ValueError("payload is encrypted — password required")
        key = _derive_key(password, salt)
        try:
            body = AESGCM(key).decrypt(nonce, body, None)
        except Exception:
            raise ValueError("decryption failed — wrong password or corrupted payload")

    if flags & FLAG_COMPRESSED:
        try:
            body = zlib.decompress(body)
        except zlib.error as exc:
            raise ValueError(f"decompression failed: {exc}")

    return {
        "encrypted": bool(flags & FLAG_ENCRYPTED),
        "compressed": bool(flags & FLAG_COMPRESSED),
        "filename": filename,
        "payload": body,
        "size": len(body),
    }


# ── Bit-level packing ─────────────────────────────────────────────────────────

def _bytes_to_bits(data: bytes) -> list[int]:
    out: list[int] = []
    for byte in data:
        for shift in (7, 6, 5, 4, 3, 2, 1, 0):
            out.append((byte >> shift) & 1)
    return out


def _bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        bits = bits[: len(bits) - (len(bits) % 8)]
    out = bytearray(len(bits) // 8)
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | (bits[i + j] & 1)
        out[i // 8] = b
    return bytes(out)


# ── Image LSB (PNG / BMP) ─────────────────────────────────────────────────────

def _image_capacity_bytes(img: Image.Image) -> int:
    """3 bits per pixel (R, G, B). Alpha is preserved untouched."""
    return (img.width * img.height * 3) // 8


def _embed_into_image(img: Image.Image, blob: bytes) -> Image.Image:
    """Return a new image with `blob` packed into the LSBs of R/G/B."""
    has_alpha = img.mode in ("RGBA", "LA") or "A" in img.getbands()
    work = img.convert("RGBA") if has_alpha else img.convert("RGB")
    pixels = bytearray(work.tobytes())
    channels = 4 if has_alpha else 3

    capacity_bits = (len(pixels) // channels) * 3
    bits = _bytes_to_bits(blob)
    if len(bits) > capacity_bits:
        raise ValueError(
            f"payload too large: {len(blob)} bytes needs "
            f"{(len(bits) + 7) // 8} of {capacity_bits // 8} available"
        )

    bit_idx = 0
    for i in range(0, len(pixels), channels):
        if bit_idx >= len(bits):
            break
        # Modify R, G, B (skip alpha)
        for c in range(3):
            if bit_idx >= len(bits):
                break
            pixels[i + c] = (pixels[i + c] & 0xFE) | bits[bit_idx]
            bit_idx += 1

    out = Image.frombytes(work.mode, work.size, bytes(pixels))
    return out


def _extract_from_image(img: Image.Image, max_bytes: int | None = None) -> bytes:
    """Pull LSB bits from R/G/B until we either hit max_bytes or run out."""
    has_alpha = img.mode in ("RGBA", "LA") or "A" in img.getbands()
    work = img.convert("RGBA") if has_alpha else img.convert("RGB")
    pixels = work.tobytes()
    channels = 4 if has_alpha else 3

    bits: list[int] = []
    bit_limit = max_bytes * 8 if max_bytes is not None else len(pixels) // channels * 3
    for i in range(0, len(pixels), channels):
        if len(bits) >= bit_limit:
            break
        for c in range(3):
            if len(bits) >= bit_limit:
                break
            bits.append(pixels[i + c] & 1)
    return _bits_to_bytes(bits)


# ── WAV LSB ───────────────────────────────────────────────────────────────────

def _wav_capacity_bytes(params: wave._wave_params) -> int:
    """1 bit per sample (LSB of each sample, regardless of width)."""
    total_samples = params.nframes * params.nchannels
    return total_samples // 8


def _embed_into_wav(blob: bytes, raw: bytes) -> bytes:
    """Return a new WAV file (bytes) with blob LSB-packed into PCM samples."""
    with wave.open(io.BytesIO(raw), "rb") as r:
        params = r.getparams()
        frames = r.readframes(params.nframes)

    if params.sampwidth not in (1, 2, 3, 4):
        raise ValueError(f"unsupported WAV sample width {params.sampwidth}")

    capacity_bits = _wav_capacity_bytes(params) * 8
    bits = _bytes_to_bits(blob)
    if len(bits) > capacity_bits:
        raise ValueError(
            f"payload too large: {len(blob)} bytes needs "
            f"{(len(bits) + 7) // 8} of {capacity_bits // 8} available"
        )

    sw = params.sampwidth
    samples = bytearray(frames)
    # Toggle the lowest-order byte (little-endian samples) — that's the LSB.
    for i, bit in enumerate(bits):
        idx = i * sw   # first byte of each sample is the lowest-order byte
        samples[idx] = (samples[idx] & 0xFE) | bit

    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setparams(params)
        w.writeframes(bytes(samples))
    return buf.getvalue()


def _extract_from_wav(raw: bytes, max_bytes: int | None = None) -> bytes:
    with wave.open(io.BytesIO(raw), "rb") as r:
        params = r.getparams()
        frames = r.readframes(params.nframes)
    sw = params.sampwidth
    total_samples = params.nframes * params.nchannels
    bit_limit = max_bytes * 8 if max_bytes is not None else total_samples
    bit_limit = min(bit_limit, total_samples)
    bits = [frames[i * sw] & 1 for i in range(bit_limit)]
    return _bits_to_bytes(bits)


# ── Format detection ──────────────────────────────────────────────────────────

def _sniff_format(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "wav"
    return "unknown"


# ── Analysis ──────────────────────────────────────────────────────────────────

def _appended_data(fmt: str, data: bytes) -> dict[str, Any]:
    """Detect bytes appended after the format's end-of-stream marker."""
    if fmt == "png":
        marker = b"IEND\xaeB`\x82"   # IEND chunk + CRC
        idx = data.rfind(marker)
        if idx == -1:
            return {"detected": False}
        tail_start = idx + len(marker)
        tail = data[tail_start:]
        return {
            "detected": len(tail) > 0,
            "offset": tail_start,
            "length": len(tail),
            "preview_hex": tail[:64].hex(),
            "printable": _printable_preview(tail),
        }
    if fmt == "jpeg":
        idx = data.rfind(b"\xff\xd9")
        if idx == -1:
            return {"detected": False}
        tail = data[idx + 2 :]
        return {
            "detected": len(tail) > 0,
            "offset": idx + 2,
            "length": len(tail),
            "preview_hex": tail[:64].hex(),
            "printable": _printable_preview(tail),
        }
    if fmt == "wav":
        # RIFF header: bytes 4-8 = chunk size (little-endian uint32) covering
        # everything after byte 8.
        if len(data) < 12:
            return {"detected": False}
        riff_size = struct.unpack("<I", data[4:8])[0]
        declared_end = 8 + riff_size
        tail = data[declared_end:] if declared_end < len(data) else b""
        return {
            "detected": len(tail) > 0,
            "offset": declared_end,
            "length": len(tail),
            "preview_hex": tail[:64].hex(),
            "printable": _printable_preview(tail),
        }
    if fmt == "bmp":
        # BMP file header bytes 2-6 = full file size, little-endian.
        if len(data) < 6:
            return {"detected": False}
        declared = struct.unpack("<I", data[2:6])[0]
        tail = data[declared:] if declared < len(data) else b""
        return {
            "detected": len(tail) > 0,
            "offset": declared,
            "length": len(tail),
            "preview_hex": tail[:64].hex(),
            "printable": _printable_preview(tail),
        }
    return {"detected": False}


def _printable_preview(tail: bytes, max_len: int = 80) -> str:
    out = []
    for b in tail[:max_len]:
        if 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def _chi_square_lsb(pixels_rgb: bytes) -> dict[str, Any]:
    """Westfeld-Pfitzmann chi-square test for LSB steganography.

    Natural images have uneven counts within each pair (2k, 2k+1); LSB-stego
    flattens those pairs. So a *low* chi² (high p-value) is suspicious.
    """
    counts = [0] * 256
    for b in pixels_rgb:
        counts[b] += 1

    chi2 = 0.0
    dof = 0
    for k in range(128):
        a, b = counts[2 * k], counts[2 * k + 1]
        if a + b == 0:
            continue
        expected = (a + b) / 2.0
        chi2 += ((a - expected) ** 2) / expected + ((b - expected) ** 2) / expected
        dof += 1

    # We're computing chi² with dof pairs (each contributes 1 dof after the
    # equality-of-means constraint), so dof_for_p = dof. p = P(X² >= chi2).
    p_value = _chi2_sf(chi2, dof) if dof > 0 else 0.0
    return {
        "chi_square": round(chi2, 3),
        "dof": dof,
        "p_value": round(p_value, 6),
        # p_value close to 1 → very likely stego; close to 0 → looks natural
        "stego_probability": round(p_value, 6),
    }


def _chi2_sf(x: float, k: int) -> float:
    """Survival function of chi-square distribution.

    Uses regularized upper incomplete gamma Q(k/2, x/2) computed via series
    expansion for small x and continued-fraction expansion for large x.
    """
    if x <= 0 or k <= 0:
        return 1.0
    a = k / 2.0
    z = x / 2.0
    return _gammaincc(a, z)


def _gammaincc(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x)."""
    if x < 0 or a <= 0:
        return 1.0
    if x < a + 1:
        # Use the series for P(a,x), then Q = 1 - P
        return 1.0 - _gammap_series(a, x)
    # Use continued fraction for Q directly
    return _gammaq_cf(a, x)


def _gammap_series(a: float, x: float, max_iter: int = 200, eps: float = 1e-12) -> float:
    ap = a
    s = 1.0 / a
    term = s
    for _ in range(max_iter):
        ap += 1
        term *= x / ap
        s += term
        if abs(term) < abs(s) * eps:
            break
    return s * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gammaq_cf(a: float, x: float, max_iter: int = 200, eps: float = 1e-12) -> float:
    # Lentz's method
    fpmin = 1e-300
    b = x + 1.0 - a
    c = 1.0 / fpmin
    d = 1.0 / b
    h = d
    for i in range(1, max_iter + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < fpmin:
            d = fpmin
        c = b + an / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _block_chi_square(pixels_rgb: bytes, blocks: int = 16) -> list[dict[str, Any]]:
    """Slice the image bytes into N equal blocks, run chi² on each.

    Stego payloads are usually embedded sequentially from the top-left, so the
    first few blocks will show high stego_probability while later ones stay
    natural — a classic Westfeld signature.
    """
    if blocks <= 1:
        return []
    n = len(pixels_rgb) // blocks
    if n < 256:   # need enough samples for chi² to mean anything
        return []
    out = []
    for i in range(blocks):
        seg = pixels_rgb[i * n : (i + 1) * n]
        res = _chi_square_lsb(seg)
        out.append({"block": i + 1, **res})
    return out


def _exif_dump(img: Image.Image) -> dict[str, Any]:
    try:
        raw = img.getexif()
    except Exception:
        return {"present": False, "tags": {}}
    if not raw:
        return {"present": False, "tags": {}}
    tags: dict[str, str] = {}
    for tag_id, val in raw.items():
        name = ExifTags.TAGS.get(tag_id, f"0x{tag_id:04x}")
        if isinstance(val, bytes):
            try:
                val = val.decode("utf-8", errors="replace")
            except Exception:
                val = val.hex()
        s = str(val)
        if len(s) > 200:
            s = s[:200] + f"… (truncated, {len(str(val))} chars)"
        tags[name] = s
    return {"present": True, "tags": tags, "count": len(tags)}


# ── REST endpoints ────────────────────────────────────────────────────────────

@router.get("/stego/info")
def info() -> dict[str, Any]:
    return {
        "magic": MAGIC.decode("ascii"),
        "version": VERSION,
        "carriers": {
            "png":  {"embed": True,  "extract": True,  "analyze": True,
                     "notes": "Lossless. LSB on R/G/B channels; alpha untouched."},
            "bmp":  {"embed": True,  "extract": True,  "analyze": True,
                     "notes": "Lossless. Same LSB scheme as PNG."},
            "jpeg": {"embed": False, "extract": False, "analyze": True,
                     "notes": "Lossy DCT — naive LSB doesn't survive. Detector inspects EXIF + appended bytes."},
            "wav":  {"embed": True,  "extract": True,  "analyze": True,
                     "notes": "PCM LSB. 1 bit/sample regardless of width."},
        },
        "encryption": "AES-256-GCM, key = scrypt(N=16384, r=8, p=1) of password",
        "compression": "zlib level 9 (kept only if it actually shrinks the payload)",
        "container_overhead_bytes": {
            "minimum":          HEADER_FIXED,
            "with_filename":    HEADER_FIXED + 1 + 255,
            "with_encryption":  HEADER_FIXED + SCRYPT_SALT_LEN + AESGCM_NONCE_LEN + AESGCM_TAG_LEN,
        },
    }


@router.post("/stego/capacity")
async def capacity(file: UploadFile = File(...)) -> dict[str, Any]:
    raw = await file.read()
    fmt = _sniff_format(raw)
    if fmt in ("png", "bmp", "jpeg"):
        try:
            img = Image.open(io.BytesIO(raw))
            img.load()
        except Exception as exc:
            raise HTTPException(400, f"failed to open image: {exc}")
        cap = _image_capacity_bytes(img) if fmt != "jpeg" else 0
        return {
            "format": fmt, "width": img.width, "height": img.height,
            "mode": img.mode,
            "capacity_bytes_raw": cap,
            "capacity_bytes_with_min_overhead": max(0, cap - HEADER_FIXED),
            "embeddable": fmt != "jpeg",
        }
    if fmt == "wav":
        try:
            with wave.open(io.BytesIO(raw), "rb") as r:
                params = r.getparams()
        except Exception as exc:
            raise HTTPException(400, f"failed to open WAV: {exc}")
        cap = _wav_capacity_bytes(params)
        return {
            "format": "wav",
            "channels": params.nchannels, "sample_width_bytes": params.sampwidth,
            "frame_rate": params.framerate, "n_frames": params.nframes,
            "capacity_bytes_raw": cap,
            "capacity_bytes_with_min_overhead": max(0, cap - HEADER_FIXED),
            "embeddable": True,
        }
    raise HTTPException(400, f"unsupported format (sniffed: {fmt})")


@router.post("/stego/embed")
async def embed(
    request: Request,
    file: UploadFile = File(...),
    payload_text: str | None = Form(None),
    payload_file: UploadFile | None = File(None),
    password: str | None = Form(None),
    compress: bool = Form(True),
    keep_filename: bool = Form(True),
) -> Response:
    """Embed a payload into the carrier file. Returns the stego bytes."""
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    if not payload_text and not payload_file:
        raise HTTPException(400, "must provide payload_text or payload_file")
    if payload_text and payload_file:
        raise HTTPException(400, "provide either payload_text or payload_file, not both")

    if payload_text:
        payload = payload_text.encode("utf-8")
        filename = None
    else:
        assert payload_file is not None
        payload = await payload_file.read()
        filename = payload_file.filename if keep_filename else None

    raw = await file.read()
    fmt = _sniff_format(raw)

    container = build_container(
        payload, password=password or None, compress=compress, filename=filename
    )

    if fmt in ("png", "bmp"):
        try:
            img = Image.open(io.BytesIO(raw))
            img.load()
        except Exception as exc:
            raise HTTPException(400, f"failed to open image: {exc}")
        try:
            stego = _embed_into_image(img, container)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        buf = io.BytesIO()
        out_fmt = "PNG" if fmt == "png" else "BMP"
        stego.save(buf, format=out_fmt)
        return Response(
            content=buf.getvalue(),
            media_type="image/png" if fmt == "png" else "image/bmp",
            headers={
                "X-Stego-Payload-Bytes": str(len(payload)),
                "X-Stego-Container-Bytes": str(len(container)),
                "Content-Disposition": f'attachment; filename="stego.{fmt}"',
            },
        )

    if fmt == "wav":
        try:
            out_bytes = _embed_into_wav(container, raw)
        except (ValueError, wave.Error) as exc:
            raise HTTPException(400, str(exc))
        return Response(
            content=out_bytes,
            media_type="audio/wav",
            headers={
                "X-Stego-Payload-Bytes": str(len(payload)),
                "X-Stego-Container-Bytes": str(len(container)),
                "Content-Disposition": 'attachment; filename="stego.wav"',
            },
        )

    raise HTTPException(400, f"embedding not supported for {fmt}")


@router.post("/stego/extract")
async def extract(
    request: Request,
    file: UploadFile = File(...),
    password: str | None = Form(None),
) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    raw = await file.read()
    fmt = _sniff_format(raw)

    if fmt in ("png", "bmp"):
        try:
            img = Image.open(io.BytesIO(raw))
            img.load()
        except Exception as exc:
            raise HTTPException(400, f"failed to open image: {exc}")
        # Pull a small prefix first to read the header, then read the rest.
        prefix = _extract_from_image(img, max_bytes=HEADER_FIXED + 256)
        full_len = _expected_total_length(prefix)
        blob = _extract_from_image(img, max_bytes=full_len) if full_len else prefix
    elif fmt == "wav":
        prefix = _extract_from_wav(raw, max_bytes=HEADER_FIXED + 256)
        full_len = _expected_total_length(prefix)
        blob = _extract_from_wav(raw, max_bytes=full_len) if full_len else prefix
    elif fmt == "jpeg":
        raise HTTPException(400, "LSB extraction is unreliable on JPEG (use /stego/analyze)")
    else:
        raise HTTPException(400, f"unsupported format (sniffed: {fmt})")

    try:
        parsed = parse_container(blob, password=password or None)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return {
        "encrypted": parsed["encrypted"],
        "compressed": parsed["compressed"],
        "filename": parsed["filename"],
        "size": parsed["size"],
        "is_text": _looks_like_text(parsed["payload"]),
        "text": _safe_text(parsed["payload"]),
        "payload_b64": base64.b64encode(parsed["payload"]).decode("ascii"),
    }


def _expected_total_length(prefix: bytes) -> int | None:
    """Read the container header from a prefix and compute the total byte length."""
    if not prefix.startswith(MAGIC) or len(prefix) < HEADER_FIXED:
        return None
    pos = len(MAGIC) + 1   # skip magic + version
    flags = prefix[pos]; pos += 1
    payload_len = struct.unpack(">I", prefix[pos : pos + 4])[0]; pos += 4

    extras = 0
    if flags & FLAG_HAS_FILENAME:
        if pos >= len(prefix):
            return None
        extras += 1 + prefix[pos]
        pos += 1
    if flags & FLAG_ENCRYPTED:
        extras += SCRYPT_SALT_LEN + AESGCM_NONCE_LEN
    return HEADER_FIXED + extras + payload_len


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable / max(1, len(s)) > 0.9


def _safe_text(data: bytes) -> str:
    if not _looks_like_text(data):
        return ""
    return data.decode("utf-8", errors="replace")


@router.post("/stego/analyze")
async def analyze(request: Request, file: UploadFile = File(...)) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    raw = await file.read()
    fmt = _sniff_format(raw)
    if fmt == "unknown":
        raise HTTPException(400, "unrecognized file format")

    result: dict[str, Any] = {"format": fmt, "size_bytes": len(raw)}

    if fmt in ("png", "bmp", "jpeg"):
        try:
            img = Image.open(io.BytesIO(raw))
            img.load()
        except Exception as exc:
            raise HTTPException(400, f"failed to open image: {exc}")
        result.update({
            "width": img.width, "height": img.height, "mode": img.mode,
            "exif": _exif_dump(img),
        })
        # LSB chi² only meaningful on lossless RGB-ish images
        if fmt in ("png", "bmp"):
            work = img.convert("RGB")
            pixels = work.tobytes()
            result["chi_square"] = _chi_square_lsb(pixels)
            result["block_analysis"] = _block_chi_square(pixels, blocks=16)
            # NTSTEG magic probe
            prefix = _extract_from_image(work, max_bytes=HEADER_FIXED + 16)
            result["ntsteg_magic_detected"] = prefix.startswith(MAGIC)
            if result["ntsteg_magic_detected"]:
                result["ntsteg_expected_total"] = _expected_total_length(prefix)
            result["capacity_bytes"] = _image_capacity_bytes(img)

    elif fmt == "wav":
        try:
            with wave.open(io.BytesIO(raw), "rb") as r:
                params = r.getparams()
                frames = r.readframes(params.nframes)
        except Exception as exc:
            raise HTTPException(400, f"failed to open WAV: {exc}")
        # For chi² on WAV, sample the low byte of each sample.
        sw = params.sampwidth
        low_bytes = bytes(frames[i] for i in range(0, len(frames), sw))
        result.update({
            "channels": params.nchannels, "sample_width": sw,
            "frame_rate": params.framerate, "n_frames": params.nframes,
            "chi_square": _chi_square_lsb(low_bytes),
            "block_analysis": _block_chi_square(low_bytes, blocks=16),
            "capacity_bytes": _wav_capacity_bytes(params),
        })
        prefix = _extract_from_wav(raw, max_bytes=HEADER_FIXED + 16)
        result["ntsteg_magic_detected"] = prefix.startswith(MAGIC)
        if result["ntsteg_magic_detected"]:
            result["ntsteg_expected_total"] = _expected_total_length(prefix)

    result["appended_data"] = _appended_data(fmt, raw)

    # Verdict: roll up the signals into a single severity tag for the UI.
    p = result.get("chi_square", {}).get("p_value", 0.0)
    blocks = result.get("block_analysis", [])
    high_blocks = sum(1 for b in blocks if b.get("p_value", 0) > 0.9)
    appended_len = result["appended_data"].get("length", 0) if result["appended_data"].get("detected") else 0
    exif_present = result.get("exif", {}).get("present", False)
    magic = result.get("ntsteg_magic_detected", False)

    signals: list[str] = []
    if magic:
        signals.append("NTSTEG magic header found in LSBs")
    if p > 0.95:
        signals.append(f"Global chi² p-value {p:.3f} — very likely LSB stego")
    elif p > 0.5 and high_blocks > 0:
        signals.append(f"{high_blocks} of {len(blocks)} blocks show LSB-flattening")
    if appended_len > 0:
        signals.append(f"{appended_len} bytes appended after end-of-file marker")
    if exif_present and result.get("exif", {}).get("count", 0) > 0:
        signals.append(f"{result['exif']['count']} EXIF tag(s) present")

    if magic or p > 0.95 or appended_len > 1024:
        severity = "high"
    elif p > 0.5 or high_blocks > 2 or appended_len > 0:
        severity = "warn"
    else:
        severity = "clean"

    result["verdict"] = {"severity": severity, "signals": signals}
    return result


@router.post("/stego/strip-metadata")
async def strip_metadata(request: Request, file: UploadFile = File(...)) -> Response:
    """Re-encode the image with all EXIF/XMP/ICC stripped."""
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    raw = await file.read()
    fmt = _sniff_format(raw)
    if fmt not in ("png", "jpeg", "bmp"):
        raise HTTPException(400, f"strip not supported for {fmt}")
    try:
        img = Image.open(io.BytesIO(raw))
        img.load()
    except Exception as exc:
        raise HTTPException(400, f"failed to open image: {exc}")

    clean = Image.new(img.mode, img.size)
    clean.putdata(list(img.getdata()))
    buf = io.BytesIO()
    save_kwargs: dict[str, Any] = {}
    if fmt == "jpeg":
        save_kwargs["quality"] = 95
    clean.save(buf, format=fmt.upper(), **save_kwargs)
    return Response(
        content=buf.getvalue(),
        media_type=f"image/{fmt}",
        headers={"Content-Disposition": f'attachment; filename="clean.{fmt}"'},
    )
