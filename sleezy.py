#!/usr/bin/env python3
r"""
   _____ __
  / ___// /__  ___  ____  __  __
  \__ \/ / _ \/ _ \/_  / / / / /
 ___/ / /  __/  __/ / /_/ /_/ /
/____/_/\___/\___/ /___/\__, /
                       /____/

Sleezy - Modular Steganography Workbench & Cryptographic Steganalysis Suite
PRD Version 1.2 | Local-Only | Zero-Telemetry | Multi-Carrier Pipeline

Implements:
  - Container format (manifest + payload, optional tar bundling for multi-file/folders)
  - Pipeline: pack -> compress -> encrypt -> scatter -> embed -> verify
  - Carrier plugins:
      * image.lsb (PNG, BMP, TIFF, WebP; 1-4 bits per channel, PRNG scattered)
      * audio.lsb (WAV 16-bit PCM, PRNG scattered)
      * text.zero-width (TXT, MD, HTML; ZWSP/ZWNJ insertion)
      * text.whitespace (TXT, MD, HTML; trailing space/tab)
      * text.homoglyph (TXT, MD, HTML; Latin <-> Cyrillic homoglyph substitution)
      * archive.comment (ZIP, DOCX, XLSX, PPTX, JAR; ZIP comment field)
      * generic.append (Any binary; EOF trailer append)
  - Steganalysis (analyze):
      * Chi-Square (χ²) analysis with degrees of freedom & p-value
      * Shannon entropy & block entropy scanning
      * LSB ratio deviation analysis
      * Bitplane 2D ASCII density visualizer (--bitplane)
      * Structural inspection (PNG chunks, ZIP comments, trailers)
  - Profile manager: ctf-quick, max-stealth, max-capacity, watermark, covert-text
  - Batch mode: glob embed/extract across entire directories
  - Watermark mode & verification
  - Interactive guided wizard
  - Interactive REPL shell with autocomplete and history
  - Exit codes matching Appendix B strictly
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import io
import json
import math
import mimetypes
import os
import random
import secrets
import shlex
import struct
import sys
import tarfile
import time
import wave
import zipfile
import zlib
from abc import ABC, abstractmethod
from array import array
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Enable UTF-8 encoding on standard streams to avoid Windows charmap errors
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Enable VT100 ANSI sequences on Windows console
if os.name == "nt":
    os.system("")

# Auto-detect readline / pyreadline3 for interactive shell tab completion
HAVE_READLINE = False
try:
    import pyreadline3 as readline
    HAVE_READLINE = True
except ImportError:
    try:
        import readline
        HAVE_READLINE = True
    except ImportError:
        HAVE_READLINE = False

# ---- optional dependencies (graceful fallback) ------------------------------
try:
    import nacl.bindings as _nacl
    HAVE_XCHACHA = True
except ImportError:
    HAVE_XCHACHA = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import zstandard as _zstd
    HAVE_ZSTD = True
except ImportError:
    HAVE_ZSTD = False

from argon2.low_level import Type as Argon2Type, hash_secret_raw

try:
    from PIL import Image
    import numpy as np
    HAVE_IMAGE = True
except ImportError:
    HAVE_IMAGE = False

try:
    import scipy.stats as _scipy_stats
    HAVE_SCIPY = True
except ImportError:
    HAVE_SCIPY = False

# ---- exit codes (Appendix B) ------------------------------------------------
EXIT_OK, EXIT_ERR, EXIT_BADARGS, EXIT_TOO_LARGE, EXIT_UNSUPPORTED = 0, 1, 2, 3, 4
EXIT_AUTH_FAILED, EXIT_VERIFY_FAILED, EXIT_NOTHING_FOUND = 5, 6, 7


class SleezyError(Exception):
    def __init__(self, msg: str, code: int = EXIT_ERR):
        super().__init__(msg)
        self.code = code


# =============================================================================
# Terminal UI & Styling Engine
# =============================================================================
class UI:
    """Rich terminal styling engine with ANSI color and graceful fallback."""
    USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    # ANSI styles
    RESET = "\x1b[0m" if USE_COLOR else ""
    BOLD = "\x1b[1m" if USE_COLOR else ""
    ITALIC = "\x1b[3m" if USE_COLOR else ""
    UNDERLINE = "\x1b[4m" if USE_COLOR else ""
    DIM = "\x1b[2m" if USE_COLOR else ""

    # ANSI 256 / 16 Colors
    CYAN = "\x1b[38;5;51m" if USE_COLOR else ""
    SKY = "\x1b[38;5;45m" if USE_COLOR else ""
    BLUE = "\x1b[38;5;39m" if USE_COLOR else ""
    PURPLE = "\x1b[38;5;141m" if USE_COLOR else ""
    MAGENTA = "\x1b[38;5;201m" if USE_COLOR else ""
    GREEN = "\x1b[38;5;48m" if USE_COLOR else ""
    YELLOW = "\x1b[38;5;220m" if USE_COLOR else ""
    ORANGE = "\x1b[38;5;208m" if USE_COLOR else ""
    RED = "\x1b[38;5;196m" if USE_COLOR else ""
    GRAY = "\x1b[38;5;244m" if USE_COLOR else ""
    WHITE = "\x1b[38;5;255m" if USE_COLOR else ""

    BANNER_GRADIENT = [CYAN, SKY, BLUE, PURPLE, MAGENTA, "\x1b[38;5;213m" if USE_COLOR else ""]

    @classmethod
    def print_banner(cls):
        """Displays the italic ASCII banner with gradient styling and system stats."""
        banner_lines = [
            r"   _____ __                            ",
            r"  / ___// /__  ___  ____  __  __       ",
            r"  \__ \/ / _ \/ _ \/_  / / / / /       ",
            r" ___/ / /  __/  __/ / /_/ /_/ /        ",
            r"/____/_/\___/\___/ /___/\__, /         ",
            r"                       /____/          ",
        ]
        print()
        for color, line in zip(cls.BANNER_GRADIENT, banner_lines):
            print(f"{cls.BOLD}{cls.ITALIC}{color}{line}{cls.RESET}")
        print(f"{cls.ITALIC}{cls.WHITE}   The Modular Steganography Workbench & Steganalysis Suite{cls.RESET}")
        print(f"{cls.ITALIC}{cls.GRAY}   v1.2.0 • Local-Only • Zero-Telemetry • Multi-Carrier Pipeline{cls.RESET}")
        print()

    @classmethod
    def print_status_panel(cls):
        """Prints diagnostics of loaded engines and plugins."""
        kdf_info = "Argon2id (64 MiB default)"
        cipher_info = f"XChaCha20-Poly1305 {'✓' if HAVE_XCHACHA else '(PyNaCl missing, using AES-GCM)'}, AES-256-GCM ✓"
        comp_info = f"Zstandard {'✓' if HAVE_ZSTD else '(fallback Deflate)'}, Deflate ✓"
        img_info = "Pillow + NumPy ✓ (lossless PNG/BMP/TIFF/WebP)" if HAVE_IMAGE else "Pillow missing"
        scipy_info = "SciPy χ² p-values ✓" if HAVE_SCIPY else "Standard χ² approximation"

        cls.box("SYSTEM DIAGNOSTICS", [
            f"{cls.CYAN}• KDF Engine:{cls.RESET}      {kdf_info}",
            f"{cls.CYAN}• Ciphers:{cls.RESET}         {cipher_info}",
            f"{cls.CYAN}• Compression:{cls.RESET}     {comp_info}",
            f"{cls.CYAN}• Image Engine:{cls.RESET}    {img_info}",
            f"{cls.CYAN}• Steganalysis:{cls.RESET}    {scipy_info}",
            f"{cls.CYAN}• Carrier Plugins:{cls.RESET} 7 active plugins loaded",
        ], color=cls.BLUE)

    @classmethod
    def box(cls, title: str, lines: list[str], color: str = ""):
        color = color or cls.CYAN
        content_plain_lengths = [len(cls._strip_ansi(l)) for l in lines]
        width = max([len(title) + 4] + content_plain_lengths + [55])
        border_top = f"┌─ {title} " + "─" * (width - len(title) - 4) + "┐"
        border_bottom = "└" + "─" * (width - 1) + "┘"
        print(f"{color}{border_top}{cls.RESET}")
        for l in lines:
            pad = width - 2 - len(cls._strip_ansi(l))
            print(f"{color}│{cls.RESET} {l}" + " " * max(pad, 0) + f"{color}│{cls.RESET}")
        print(f"{color}{border_bottom}{cls.RESET}")

    @classmethod
    def gauge(cls, rate: float, width: int = 24) -> str:
        """Renders an ASCII capacity gauge bar."""
        rate = max(0.0, min(1.0, rate))
        filled = int(round(rate * width))
        empty = width - filled
        pct = rate * 100.0
        if rate <= 0.30:
            color = cls.GREEN
        elif rate <= 0.70:
            color = cls.YELLOW
        else:
            color = cls.RED
        bar = f"{color}█" * filled + f"{cls.GRAY}░" * empty + cls.RESET
        return f"[{bar}] {color}{pct:5.1f}%{cls.RESET}"

    @classmethod
    def risk_badge(cls, score: int) -> str:
        """Returns color-coded detectability risk pill."""
        score = max(0, min(100, score))
        if score <= 30:
            return f"{cls.GREEN}[LOW RISK {score}/100]{cls.RESET}"
        elif score <= 60:
            return f"{cls.YELLOW}[MEDIUM RISK {score}/100]{cls.RESET}"
        else:
            return f"{cls.RED}[HIGH RISK {score}/100]{cls.RESET}"

    @classmethod
    def table(cls, headers: list[str], rows: list[list[str]]):
        """Prints a clean Unicode table."""
        col_widths = [len(cls._strip_ansi(h)) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(cls._strip_ansi(str(cell))))

        def make_row(cells, sep="│", pad_char=" "):
            out = []
            for c, w in zip(cells, col_widths):
                p_len = len(cls._strip_ansi(str(c)))
                out.append(f" {c}" + pad_char * (w - p_len + 1))
            return sep + sep.join(out) + sep

        top = "┌" + "┬".join("─" * (w + 2) for w in col_widths) + "┐"
        mid = "├" + "┼".join("─" * (w + 2) for w in col_widths) + "┤"
        bot = "└" + "┴".join("─" * (w + 2) for w in col_widths) + "┘"

        print(cls.CYAN + top + cls.RESET)
        print(cls.BOLD + cls.CYAN + make_row(headers) + cls.RESET)
        print(cls.CYAN + mid + cls.RESET)
        for r in rows:
            print(make_row(r))
        print(cls.CYAN + bot + cls.RESET)

    @classmethod
    def ok(cls, msg: str):
        print(f"{cls.GREEN}[OK]{cls.RESET} {msg}")

    @classmethod
    def info(cls, msg: str):
        print(f"{cls.BLUE}[INFO]{cls.RESET} {msg}")

    @classmethod
    def warn(cls, msg: str):
        print(f"{cls.YELLOW}[WARN]{cls.RESET} {msg}")

    @classmethod
    def err(cls, msg: str):
        print(f"{cls.RED}[ERROR]{cls.RESET} {msg}", file=sys.stderr)

    @staticmethod
    def _strip_ansi(text: str) -> str:
        import re
        return re.sub(r"\x1b\[[0-9;]*m", "", text)


# =============================================================================
# Outer header (fixed-size 63-byte struct, sequential at start of carrier)
# =============================================================================
MAGIC = b"SLEEZY01"
HEADER_FMT = ">8sBBBBBBB16s24sQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 63 bytes
HEADER_BITS = HEADER_SIZE * 8

CIPHERS = {0: "aes-256-gcm", 1: "xchacha20poly1305"}
CIPHERS_R = {v: k for k, v in CIPHERS.items()}
COMPRESSORS = {0: "none", 1: "deflate", 2: "zstd"}
COMPRESSORS_R = {v: k for k, v in COMPRESSORS.items()}


@dataclass
class OuterHeader:
    cipher: str
    compress: str
    time_cost: int
    mem_cost_exp: int  # memory = 2**mem_cost_exp KiB
    parallelism: int
    salt: bytes
    nonce: bytes
    ciphertext_len: int

    def pack(self) -> bytes:
        nonce_padded = self.nonce.ljust(24, b"\x00")
        return struct.pack(
            HEADER_FMT, MAGIC, 1, CIPHERS_R[self.cipher], 0, COMPRESSORS_R[self.compress],
            self.time_cost, self.mem_cost_exp, self.parallelism,
            self.salt, nonce_padded, self.ciphertext_len,
        )

    @staticmethod
    def unpack(buf: bytes) -> "OuterHeader":
        if len(buf) < HEADER_SIZE:
            raise SleezyError("Nothing detected: carrier too small for a Sleezy header", EXIT_NOTHING_FOUND)
        magic, ver, cid, kdf_id, comp_id, tc, mce, par, salt, nonce, ctlen = struct.unpack(
            HEADER_FMT, buf[:HEADER_SIZE]
        )
        if magic != MAGIC:
            raise SleezyError("Nothing detected: no Sleezy magic found", EXIT_NOTHING_FOUND)
        if cid not in CIPHERS or comp_id not in COMPRESSORS:
            raise SleezyError("Unsupported header (corrupt or unknown version)", EXIT_UNSUPPORTED)
        nonce_len = 12 if CIPHERS[cid] == "aes-256-gcm" else 24
        return OuterHeader(CIPHERS[cid], COMPRESSORS[comp_id], tc, mce, par, salt, nonce[:nonce_len], ctlen)


# =============================================================================
# Crypto + compression + KDF (Keyfile support included)
# =============================================================================
def kdf_derive(passphrase: bytes, salt: bytes, time_cost: int, mem_cost_exp: int, parallelism: int) -> bytes:
    """Argon2id key derivation yielding 64 bytes (32B encryption key + 32B scatter seed)."""
    return hash_secret_raw(
        secret=passphrase, salt=salt, time_cost=time_cost,
        memory_cost=2 ** mem_cost_exp, parallelism=parallelism,
        hash_len=64, type=Argon2Type.ID,
    )


def prepare_secret(passphrase: str, keyfile_path: Optional[Path] = None) -> bytes:
    """Combines passphrase with optional keyfile SHA-256 hash."""
    secret = passphrase.encode("utf-8")
    if keyfile_path:
        if not keyfile_path.exists():
            raise SleezyError(f"Keyfile not found: {keyfile_path}", EXIT_BADARGS)
        kf_hash = hashlib.sha256(keyfile_path.read_bytes()).digest()
        secret = secret + b"::KEYFILE::" + kf_hash
    return secret


def compress(data: bytes, algo: str) -> bytes:
    if algo == "zstd" and HAVE_ZSTD:
        return _zstd.ZstdCompressor(level=12).compress(data)
    if algo == "zstd" and not HAVE_ZSTD:
        algo = "deflate"
    if algo == "deflate":
        return zlib.compress(data, 9)
    return data


def decompress(data: bytes, algo: str) -> bytes:
    if algo == "zstd":
        if not HAVE_ZSTD:
            raise SleezyError("zstandard not installed, cannot decompress", EXIT_ERR)
        return _zstd.ZstdDecompressor().decompress(data)
    if algo == "deflate":
        return zlib.decompress(data)
    return data


def encrypt(plaintext: bytes, key: bytes, nonce: bytes, cipher: str, aad: bytes = b"") -> bytes:
    if cipher == "xchacha20poly1305":
        return _nacl.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    aes = AESGCM(key)
    return aes.encrypt(nonce, plaintext, aad)


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, cipher: str, aad: bytes = b"") -> bytes:
    try:
        if cipher == "xchacha20poly1305":
            return _nacl.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)
        aes = AESGCM(key)
        return aes.decrypt(nonce, ciphertext, aad)
    except Exception as e:
        raise SleezyError(f"Authentication or decryption failed: {e}", EXIT_AUTH_FAILED)


def resolve_cipher(requested: str) -> str:
    if requested == "xchacha20poly1305" and not HAVE_XCHACHA:
        sys.stderr.write("[warn] PyNaCl not installed; falling back to AES-256-GCM\n")
        return "aes-256-gcm"
    return requested


# =============================================================================
# Container Packing / Unpacking (Manifest + Payload + Optional Tar)
# =============================================================================
def pack_container(payload_paths: list[Path], raw_text: Optional[str], watermark: Optional[str] = None) -> bytes:
    """Build manifest(json) + payload bytes blob. Multi-files/folders -> tar."""
    manifest = {}
    if watermark:
        manifest["watermark"] = watermark

    if raw_text is not None:
        data = raw_text.encode("utf-8")
        manifest.update({"mode": "text", "files": [{
            "name": "payload.txt", "mime": "text/plain", "size": len(data),
            "mtime": int(time.time()), "sha256": hashlib.sha256(data).hexdigest(),
        }]})
        blob = data
    elif len(payload_paths) == 1 and payload_paths[0].is_file():
        p = payload_paths[0]
        data = p.read_bytes()
        mime = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        manifest.update({"mode": "single", "files": [{
            "name": p.name, "mime": mime, "size": len(data),
            "mtime": int(p.stat().st_mtime), "sha256": hashlib.sha256(data).hexdigest(),
        }]})
        blob = data
    else:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for p in payload_paths:
                tar.add(p, arcname=p.name)
        blob = buf.getvalue()
        manifest.update({"mode": "tar", "files": [{
            "name": "payload.tar", "mime": "application/x-tar", "size": len(blob),
            "mtime": int(time.time()), "sha256": hashlib.sha256(blob).hexdigest(),
        }]})

    manifest_bytes = json.dumps(manifest).encode("utf-8")
    return struct.pack(">I", len(manifest_bytes)) + manifest_bytes + blob


def unpack_container(blob: bytes, out_dir: Path) -> dict:
    (mlen,) = struct.unpack(">I", blob[:4])
    manifest = json.loads(blob[4:4 + mlen].decode("utf-8"))
    payload = blob[4 + mlen:]
    info = manifest["files"][0]
    actual_hash = hashlib.sha256(payload).hexdigest()
    integrity_ok = actual_hash == info["sha256"]
    out_dir.mkdir(parents=True, exist_ok=True)
    if manifest["mode"] == "text":
        (out_dir / info["name"]).write_text(payload.decode("utf-8"), encoding="utf-8")
        result_path = str(out_dir / info["name"])
    elif manifest["mode"] == "tar":
        buf = io.BytesIO(payload)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            tar.extractall(out_dir, filter="data")
        result_path = str(out_dir)
    else:
        (out_dir / info["name"]).write_bytes(payload)
        result_path = str(out_dir / info["name"])
    return {
        "manifest": manifest,
        "integrity_ok": integrity_ok,
        "output": result_path,
        "watermark": manifest.get("watermark"),
    }


# =============================================================================
# Method Plugin Architecture
# =============================================================================
class Method(ABC):
    id: str
    family: str
    display_name: str
    mode: str  # "bitplane" or "blob"
    detectability_baseline: str  # low | medium | high
    robustness: str  # none | recompress | resize | noise

    @abstractmethod
    def load(self, path: Path):
        ...


class BitplaneMethod(Method):
    mode = "bitplane"

    @abstractmethod
    def capacity_bits(self, carrier) -> int: ...

    @abstractmethod
    def read_bit(self, carrier, idx: int) -> int: ...

    @abstractmethod
    def write_bit(self, carrier, idx: int, bit: int) -> None: ...

    @abstractmethod
    def save(self, carrier, out_path: Path) -> None: ...


class BlobMethod(Method):
    mode = "blob"

    @abstractmethod
    def capacity_bytes(self, path: Path) -> int: ...

    @abstractmethod
    def embed_blob(self, path: Path, out_path: Path, blob: bytes) -> None: ...

    @abstractmethod
    def extract_blob(self, path: Path) -> bytes: ...


# ---- 1. Image LSB (PNG, BMP, TIFF, WebP) with 1-4 bits per channel ---------
class ImageLsbMethod(BitplaneMethod):
    id = "lsb"
    family = "image"
    display_name = "Lossless Image LSB (1-4 bits, scattered)"
    detectability_baseline = "medium"
    robustness = "none"

    def __init__(self, bits: int = 1, channels: str = "rgb"):
        self.bits = max(1, min(4, bits))
        self.channels = channels.lower()

    def load(self, path: Path):
        if not HAVE_IMAGE:
            raise SleezyError("Pillow/numpy not installed", EXIT_ERR)
        img = Image.open(path).convert("RGB")
        return {"arr": np.array(img, dtype=np.uint8), "bits": self.bits}

    def capacity_bits(self, carrier) -> int:
        arr = carrier["arr"]
        h, w, c = arr.shape
        return h * w * c * carrier["bits"]

    def _loc(self, carrier, idx: int):
        arr = carrier["arr"]
        bits = carrier["bits"]
        h, w, c = arr.shape
        channel_slot = idx // bits
        bit_pos = idx % bits
        pix = channel_slot // c
        ch = channel_slot % c
        return pix // w, pix % w, ch, bit_pos

    def read_bit(self, carrier, idx: int) -> int:
        r, col, ch, bit_pos = self._loc(carrier, idx)
        return int((carrier["arr"][r, col, ch] >> bit_pos) & 1)

    def write_bit(self, carrier, idx: int, bit: int):
        r, col, ch, bit_pos = self._loc(carrier, idx)
        val = carrier["arr"][r, col, ch]
        carrier["arr"][r, col, ch] = (val & ~(1 << bit_pos)) | (bit << bit_pos)

    def save(self, carrier, out_path: Path):
        Image.fromarray(carrier["arr"], mode="RGB").save(out_path)


# ---- 2. Audio LSB (WAV 16-bit PCM) ------------------------------------------
class WavLsbMethod(BitplaneMethod):
    id = "lsb"
    family = "audio"
    display_name = "WAV PCM Audio LSB (scattered)"
    detectability_baseline = "low"
    robustness = "none"

    def load(self, path: Path):
        with wave.open(str(path), "rb") as w:
            params = w.getparams()
            frames = w.readframes(w.getnframes())
        if params.sampwidth != 2:
            raise SleezyError("Only 16-bit PCM WAV supported in this build", EXIT_UNSUPPORTED)
        samples = array("h")
        samples.frombytes(frames)
        return {"params": params, "samples": samples}

    def capacity_bits(self, carrier) -> int:
        return len(carrier["samples"])

    def read_bit(self, carrier, idx: int) -> int:
        return carrier["samples"][idx] & 1

    def write_bit(self, carrier, idx: int, bit: int):
        s = carrier["samples"]
        s[idx] = (s[idx] & ~1) | bit

    def save(self, carrier, out_path: Path):
        with wave.open(str(out_path), "wb") as w:
            w.setparams(carrier["params"])
            w.writeframes(carrier["samples"].tobytes())


# ---- 3. Text Zero-Width Insertion -------------------------------------------
ZW_ONE, ZW_ZERO = "\u200b", "\u200c"


class TextZeroWidthMethod(BitplaneMethod):
    id = "zero-width"
    family = "text"
    display_name = "Zero-Width Unicode (ZWSP/ZWNJ)"
    detectability_baseline = "low"
    robustness = "none"

    def load(self, path: Path):
        raw = path.read_text(encoding="utf-8")
        chars, existing = [], {}
        gap, i = 0, 0
        while i < len(raw):
            c = raw[i]
            if c in (ZW_ONE, ZW_ZERO):
                existing[gap - 1] = 1 if c == ZW_ONE else 0
                i += 1
                continue
            chars.append(c)
            gap += 1
            i += 1
        return {"chars": chars, "existing": existing, "inserts": {}}

    def capacity_bits(self, carrier) -> int:
        return max(len(carrier["chars"]) - 1, 0)

    def read_bit(self, carrier, idx: int) -> int:
        if idx not in carrier["existing"]:
            raise SleezyError("Nothing detected at expected zero-width slot", EXIT_NOTHING_FOUND)
        return carrier["existing"][idx]

    def write_bit(self, carrier, idx: int, bit: int):
        carrier["inserts"][idx] = bit

    def save(self, carrier, out_path: Path):
        out = []
        for i, c in enumerate(carrier["chars"]):
            out.append(c)
            if i in carrier["inserts"]:
                out.append(ZW_ONE if carrier["inserts"][i] else ZW_ZERO)
        out_path.write_text("".join(out), encoding="utf-8")


# ---- 4. Text Whitespace -----------------------------------------------------
class TextWhitespaceMethod(BitplaneMethod):
    id = "whitespace"
    family = "text"
    display_name = "Trailing Whitespace per line"
    detectability_baseline = "medium"
    robustness = "none"

    def load(self, path: Path):
        lines = [ln.rstrip(" \t") for ln in path.read_text(encoding="utf-8").splitlines()]
        raw_lines = path.read_text(encoding="utf-8").splitlines()
        existing = {}
        for i, raw in enumerate(raw_lines):
            if raw.endswith(" ") and not raw.endswith("\t"):
                existing[i] = 1
            elif raw.endswith("\t"):
                existing[i] = 0
        return {"lines": lines, "existing": existing, "writes": {}}

    def capacity_bits(self, carrier) -> int:
        return len(carrier["lines"])

    def read_bit(self, carrier, idx: int) -> int:
        if idx not in carrier["existing"]:
            raise SleezyError("Nothing detected at expected whitespace slot", EXIT_NOTHING_FOUND)
        return carrier["existing"][idx]

    def write_bit(self, carrier, idx: int, bit: int):
        carrier["writes"][idx] = bit

    def save(self, carrier, out_path: Path):
        out_lines = list(carrier["lines"])
        for i, bit in carrier["writes"].items():
            out_lines[i] = out_lines[i] + (" " if bit else "\t")
        out_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")


# ---- 5. Text Homoglyphs (Cyrillic <-> Latin) --------------------------------
HOMOGLYPH_MAP = {
    "a": "\u0430", "c": "\u0441", "e": "\u0435", "i": "\u0456", "j": "\u0458",
    "o": "\u043e", "p": "\u0440", "s": "\u0455", "x": "\u0445", "y": "\u0443",
    "A": "\u0410", "C": "\u0421", "E": "\u0415", "I": "\u0406", "J": "\u0408",
    "O": "\u041e", "P": "\u0420", "S": "\u0405", "X": "\u0425", "Y": "\u04ae",
}
REV_HOMOGLYPH_MAP = {v: k for k, v in HOMOGLYPH_MAP.items()}


class TextHomoglyphMethod(BitplaneMethod):
    id = "homoglyph"
    family = "text"
    display_name = "Unicode Homoglyph Substitution (Latin/Cyrillic)"
    detectability_baseline = "low"
    robustness = "recompress"

    def load(self, path: Path):
        text = path.read_text(encoding="utf-8")
        chars = list(text)
        slots = []
        for i, ch in enumerate(chars):
            if ch in HOMOGLYPH_MAP:
                slots.append(i)
            elif ch in REV_HOMOGLYPH_MAP:
                slots.append(i)
        return {"chars": chars, "slots": slots}

    def capacity_bits(self, carrier) -> int:
        return len(carrier["slots"])

    def read_bit(self, carrier, idx: int) -> int:
        pos = carrier["slots"][idx]
        ch = carrier["chars"][pos]
        if ch in REV_HOMOGLYPH_MAP:
            return 1
        elif ch in HOMOGLYPH_MAP:
            return 0
        raise SleezyError("Invalid homoglyph slot state", EXIT_NOTHING_FOUND)

    def write_bit(self, carrier, idx: int, bit: int):
        pos = carrier["slots"][idx]
        ch = carrier["chars"][pos]
        if bit == 1:
            if ch in HOMOGLYPH_MAP:
                carrier["chars"][pos] = HOMOGLYPH_MAP[ch]
        else:
            if ch in REV_HOMOGLYPH_MAP:
                carrier["chars"][pos] = REV_HOMOGLYPH_MAP[ch]

    def save(self, carrier, out_path: Path):
        out_path.write_text("".join(carrier["chars"]), encoding="utf-8")


# ---- 6. Archive / ZIP Comment -----------------------------------------------
class ArchiveCommentMethod(BlobMethod):
    id = "comment"
    family = "archive"
    display_name = "ZIP/Office Document Comment Container"
    detectability_baseline = "medium"
    robustness = "none"

    def load(self, path: Path):
        return path

    def capacity_bytes(self, path: Path) -> int:
        return 65535  # Max standard ZIP comment size (16-bit uint)

    def embed_blob(self, path: Path, out_path: Path, blob: bytes) -> None:
        if len(blob) > 65535:
            raise SleezyError("Payload exceeds ZIP comment limit (65535 bytes)", EXIT_TOO_LARGE)
        data = path.read_bytes()
        buf = io.BytesIO(data)
        out_buf = io.BytesIO()
        try:
            with zipfile.ZipFile(buf, "r") as z_in:
                with zipfile.ZipFile(out_buf, "w", compression=zipfile.ZIP_DEFLATED) as z_out:
                    for item in z_in.infolist():
                        z_out.writestr(item, z_in.read(item.filename))
                    z_out.comment = blob
            out_path.write_bytes(out_buf.getvalue())
        except zipfile.BadZipFile:
            raise SleezyError("Carrier is not a valid ZIP/Office archive", EXIT_UNSUPPORTED)

    def extract_blob(self, path: Path) -> bytes:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                if not zf.comment:
                    raise SleezyError("Nothing detected: no ZIP comment found", EXIT_NOTHING_FOUND)
                return zf.comment
        except zipfile.BadZipFile:
            raise SleezyError("Not a valid ZIP archive", EXIT_UNSUPPORTED)


# ---- 7. Generic EOF Append --------------------------------------------------
TRAILER_MAGIC = b"SLZTRAIL"


class GenericAppendMethod(BlobMethod):
    id = "append"
    family = "generic"
    display_name = "EOF Trailer Append (any file)"
    detectability_baseline = "high"
    robustness = "none"

    def load(self, path: Path):
        return path

    def capacity_bytes(self, path: Path) -> int:
        return 2 ** 40  # effectively unlimited

    def embed_blob(self, path: Path, out_path: Path, blob: bytes) -> None:
        data = path.read_bytes()
        with open(out_path, "wb") as f:
            f.write(data)
            f.write(TRAILER_MAGIC)
            f.write(struct.pack(">Q", len(blob)))
            f.write(blob)

    def extract_blob(self, path: Path) -> bytes:
        data = path.read_bytes()
        idx = data.rfind(TRAILER_MAGIC)
        if idx == -1:
            raise SleezyError("Nothing detected: no Sleezy trailer found", EXIT_NOTHING_FOUND)
        off = idx + len(TRAILER_MAGIC)
        (blen,) = struct.unpack(">Q", data[off:off + 8])
        blob = data[off + 8:off + 8 + blen]
        if len(blob) != blen:
            raise SleezyError("Trailer truncated/corrupt", EXIT_ERR)
        return blob


# ---- Registry Setup ---------------------------------------------------------
_png = ImageLsbMethod()
_wav = WavLsbMethod()
_zw = TextZeroWidthMethod()
_ws = TextWhitespaceMethod()
_homo = TextHomoglyphMethod()
_zip = ArchiveCommentMethod()
_gen = GenericAppendMethod()

METHODS_BY_ID: dict[str, Method] = {
    "image.lsb": _png,
    "audio.lsb": _wav,
    "text.zero-width": _zw,
    "text.whitespace": _ws,
    "text.homoglyph": _homo,
    "archive.comment": _zip,
    "generic.append": _gen,
}


def pick_method(carrier_path: Path, method_name: Optional[str] = None) -> Method:
    ext = carrier_path.suffix.lower().lstrip(".")
    if method_name:
        for mid, m in METHODS_BY_ID.items():
            if mid == method_name or m.id == method_name:
                return m
        raise SleezyError(f"Unknown method '{method_name}'", EXIT_UNSUPPORTED)
    if ext in ("png", "bmp", "tiff", "webp"):
        return _png
    if ext == "wav":
        return _wav
    if ext in ("txt", "md", "html", "htm", "py", "c", "js"):
        return _zw
    if ext in ("zip", "docx", "xlsx", "pptx", "jar", "apk"):
        return _zip
    return _gen


# =============================================================================
# Detectability Heuristics & Recommendations
# =============================================================================
BASELINE_SCORE = {"low": 12, "medium": 35, "high": 68}


def detectability_score(method: Method, embedding_rate: float) -> int:
    base = BASELINE_SCORE.get(method.detectability_baseline, 35)
    score = base + embedding_rate * 58
    return max(0, min(100, round(score)))


def recommendation(rate: float, score: int) -> str:
    if rate > 0.9:
        return f"Payload uses {rate*100:.0f}% of capacity. Reduce below 30% or choose a larger carrier to mitigate detection."
    if score > 60:
        return f"Detectability score {score}/100 is high. Consider using a noisier carrier or a lower embedding rate."
    if rate > 0.3:
        return f"Payload uses {rate*100:.0f}% of capacity ({score}/100 score). Optimal security margin is under 30%."
    return f"Excellent security posture: {rate*100:.1f}% capacity used, detectability score {score}/100."


# =============================================================================
# Core Pipeline: Embed & Extract
# =============================================================================
DEFAULT_TIME_COST, DEFAULT_MEM_EXP, DEFAULT_PARALLELISM = 3, 16, 1  # 64 MiB


def _scatter_positions(scatter_seed: bytes, start: int, end: int, count: int) -> list[int]:
    rng = random.Random(scatter_seed)
    pool = list(range(start, end))
    rng.shuffle(pool)
    if count > len(pool):
        raise SleezyError("Internal error: scatter pool smaller than needed", EXIT_ERR)
    return pool[:count]


def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i + 8]:
            b = (b << 1) | bit
        out.append(b)
    return bytes(out)


def do_embed(carrier_path: Path, out_path: Path, payload_paths: list[Path], raw_text: Optional[str],
             passphrase: str, method_name: Optional[str] = None, cipher: str = "xchacha20poly1305",
             compress_algo: str = "zstd", keyfile: Optional[Path] = None, watermark: Optional[str] = None,
             bits_per_channel: int = 1, dry_run: bool = False, quiet: bool = False) -> dict:
    """Executes the full pack -> compress -> encrypt -> scatter -> embed -> verify pipeline."""
    method = pick_method(carrier_path, method_name)
    if isinstance(method, ImageLsbMethod):
        method.bits = bits_per_channel

    cipher = resolve_cipher(cipher)
    inner = pack_container(payload_paths, raw_text, watermark=watermark)
    comp = compress(inner, compress_algo)
    actual_compress = compress_algo if (compress_algo != "zstd" or HAVE_ZSTD) else "deflate"

    salt = secrets.token_bytes(16)
    secret = prepare_secret(passphrase, keyfile)
    km = kdf_derive(secret, salt, DEFAULT_TIME_COST, DEFAULT_MEM_EXP, DEFAULT_PARALLELISM)
    enc_key, scatter_seed = km[:32], km[32:64]

    nonce_len = 12 if cipher == "aes-256-gcm" else 24
    nonce = secrets.token_bytes(nonce_len)
    ciphertext = encrypt(comp, enc_key, nonce, cipher)

    header = OuterHeader(cipher, actual_compress, DEFAULT_TIME_COST, DEFAULT_MEM_EXP,
                         DEFAULT_PARALLELISM, salt, nonce, len(ciphertext))
    header_bytes = header.pack()

    if method.mode == "blob":
        total_needed = len(header_bytes) + len(ciphertext)
        capacity = method.capacity_bytes(carrier_path)
        rate = total_needed / capacity if capacity else 1.0
        needed_val = total_needed
        unit = "bytes"
    else:
        carrier = method.load(carrier_path)
        capacity = method.capacity_bits(carrier)
        needed_bits = HEADER_BITS + len(ciphertext) * 8
        rate = needed_bits / capacity if capacity else 1.0
        needed_val = needed_bits
        unit = "bits"

    score = detectability_score(method, rate)
    report = {
        "method": f"{method.family}.{method.id}",
        "capacity": capacity,
        "needed": needed_val,
        "unit": unit,
        "embedding_rate": round(rate, 4),
        "detectability_score": score,
        "recommendation": recommendation(rate, score),
    }

    if not quiet:
        if sys.stdout.isatty():
            UI.box("EMBEDDING METRICS & DETECTION RISK", [
                f"{UI.CYAN}• Method:{UI.RESET}         {report['method']} ({method.display_name})",
                f"{UI.CYAN}• Carrier Capacity:{UI.RESET} {capacity:,} {unit}",
                f"{UI.CYAN}• Payload Needed:{UI.RESET}   {needed_val:,} {unit}",
                f"{UI.CYAN}• Embedding Gauge:{UI.RESET}  {UI.gauge(rate)}",
                f"{UI.CYAN}• Detectability:{UI.RESET}    {UI.risk_badge(score)}",
                f"{UI.CYAN}• Assessment:{UI.RESET}       {report['recommendation']}",
            ], color=UI.CYAN)
        else:
            print(json.dumps(report, indent=2))

    if method.mode == "bitplane" and needed_bits > capacity:
        raise SleezyError("Payload too large for carrier", EXIT_TOO_LARGE)
    if method.mode == "blob" and total_needed > capacity:
        raise SleezyError("Payload too large for carrier", EXIT_TOO_LARGE)
    if dry_run:
        report["dry_run"] = True
        return report

    if method.mode == "blob":
        full = header_bytes + ciphertext
        method.embed_blob(carrier_path, out_path, full)
    else:
        for i, bit in enumerate(_bytes_to_bits(header_bytes)):
            method.write_bit(carrier, i, bit)
        positions = _scatter_positions(scatter_seed, HEADER_BITS, capacity, len(ciphertext) * 8)
        for bit, pos in zip(_bytes_to_bits(ciphertext), positions):
            method.write_bit(carrier, pos, bit)
        method.save(carrier, out_path)

    # ---- Verify Step: Re-extract in memory before declaring success ----------
    verify_dir = out_path.parent / f".sleezy_verify_{secrets.token_hex(4)}"
    try:
        extracted = do_extract(
            out_path, verify_dir, passphrase, method_name=f"{method.family}.{method.id}",
            keyfile=keyfile, quiet=True, _internal_verify=True
        )
        if not extracted.get("integrity_ok", False):
            out_path.unlink(missing_ok=True)
            raise SleezyError("Verification failed after embed (hash mismatch)", EXIT_VERIFY_FAILED)
    finally:
        import shutil
        shutil.rmtree(verify_dir, ignore_errors=True)

    report["output"] = str(out_path)
    if not quiet:
        UI.ok(f"Embedded & verified successfully -> {out_path}")
    return report


def do_extract(stego_path: Path, out_dir: Path, passphrase: str, method_name: Optional[str] = None,
               keyfile: Optional[Path] = None, auto: bool = False, quiet: bool = False,
               _internal_verify: bool = False) -> dict:
    """Recovers payload from carrier, verifying integrity."""
    candidates = [METHODS_BY_ID[method_name]] if method_name and not auto else list(dict.fromkeys(
        [pick_method(stego_path, None)] + list(METHODS_BY_ID.values())
    ))
    last_err = None
    best_err = None

    for method in candidates:
        try:
            if method.mode == "blob":
                full = method.extract_blob(stego_path)
                header = OuterHeader.unpack(full)
                ciphertext = full[HEADER_SIZE:HEADER_SIZE + header.ciphertext_len]
            else:
                carrier = method.load(stego_path)
                capacity = method.capacity_bits(carrier)
                if capacity < HEADER_BITS:
                    continue
                header_bits = [method.read_bit(carrier, i) for i in range(HEADER_BITS)]
                header = OuterHeader.unpack(_bits_to_bytes(header_bits))

                secret = prepare_secret(passphrase, keyfile)
                km = kdf_derive(secret, header.salt, header.time_cost,
                                header.mem_cost_exp, header.parallelism)
                scatter_seed = km[32:64]
                positions = _scatter_positions(scatter_seed, HEADER_BITS, capacity, header.ciphertext_len * 8)
                cipher_bits = [method.read_bit(carrier, p) for p in positions]
                ciphertext = _bits_to_bytes(cipher_bits)

            secret = prepare_secret(passphrase, keyfile)
            km = kdf_derive(secret, header.salt, header.time_cost,
                            header.mem_cost_exp, header.parallelism)
            enc_key = km[:32]
            comp = decrypt(ciphertext, enc_key, header.nonce, header.cipher)
            inner = decompress(comp, header.compress)
            result = unpack_container(inner, out_dir)
            result["method"] = f"{method.family}.{method.id}"

            if not quiet:
                if sys.stdout.isatty():
                    UI.box("EXTRACTION VERIFIED", [
                        f"{UI.CYAN}• Method:{UI.RESET}        {result['method']}",
                        f"{UI.CYAN}• Integrity SHA256:{UI.RESET} {'MATCH (Bit-exact)' if result['integrity_ok'] else 'FAIL'}",
                        f"{UI.CYAN}• Target Output:{UI.RESET}   {result['output']}",
                        f"{UI.CYAN}• Watermark:{UI.RESET}       {result.get('watermark') or 'None'}",
                    ], color=UI.GREEN)
                else:
                    print(json.dumps({k: v for k, v in result.items() if k != "manifest"}, indent=2))
                print(f"[ok] extracted -> {result['output']}")
            return result

        except SleezyError as e:
            last_err = e
            if e.code != EXIT_NOTHING_FOUND:
                best_err = e
            if not auto and method_name:
                raise
            continue
        except Exception as e:
            last_err = SleezyError(f"{method.family}.{method.id}: {e}", EXIT_NOTHING_FOUND)
            if not auto and method_name:
                raise SleezyError(str(e), EXIT_ERR)
            continue

    if _internal_verify:
        raise SleezyError("verify: extraction failed", EXIT_VERIFY_FAILED)
    raise best_err or last_err or SleezyError("Nothing detected: no method succeeded", EXIT_NOTHING_FOUND)


# =============================================================================
# Steganalysis Engine (Chi-Square, Entropy, LSB, Bitplane Visualizer)
# =============================================================================
def do_analyze(path: Path, deep: bool = False, bitplane: bool = False) -> dict:
    """Comprehensive structural & statistical steganalysis."""
    size = path.stat().st_size
    report = {"file": str(path), "size": size}
    ext = path.suffix.lower().lstrip(".")

    if ext in ("png", "bmp", "tiff", "webp") and HAVE_IMAGE:
        img = Image.open(path).convert("RGB")
        arr = np.array(img, dtype=np.uint8)
        lsb = arr & 1
        ones = int(lsb.sum())
        total = lsb.size
        ratio = ones / total
        deviation = abs(ratio - 0.5)

        # Chi-Square (χ²) test across pixel pairs of values (PoVs)
        counts = np.bincount(arr.flatten(), minlength=256)
        evens = counts[0::2]
        odds = counts[1::2]
        expected = (evens + odds) / 2.0
        mask = expected > 0
        chi2_val = float(np.sum(((evens[mask] - expected[mask]) ** 2) / expected[mask]))
        df = int(np.sum(mask))

        p_value = 1.0
        if HAVE_SCIPY:
            p_value = float(_scipy_stats.chi2.sf(chi2_val, df))

        # Suspicion heuristic combining LSB ratio deviation and chi2 p-value
        suspicion = min(100, round(deviation * 400))
        if p_value > 0.95 and total > 5000:
            suspicion = max(suspicion, 75)

        report.update({
            "type": "image",
            "dimensions": f"{img.width}x{img.height}",
            "channels": 3,
            "lsb_one_ratio": round(ratio, 4),
            "chi2_statistic": round(chi2_val, 2),
            "degrees_of_freedom": df,
            "chi2_p_value": round(p_value, 4),
            "suspicion_score": suspicion,
            "note": "near-exactly 0.5 LSB ratio or high chi2 p-value strongly suggests stego embedding",
        })

        if bitplane:
            report["bitplane_ascii"] = render_bitplane_ascii(lsb[:, :, 0])

    elif ext == "wav":
        with wave.open(str(path), "rb") as w:
            frames = w.readframes(w.getnframes())
        samples = array("h")
        samples.frombytes(frames)
        if samples:
            ones = sum(s & 1 for s in samples)
            ratio = ones / len(samples)
            suspicion = min(100, round(abs(ratio - 0.5) * 400))
            report.update({
                "type": "audio",
                "samples": len(samples),
                "lsb_one_ratio": round(ratio, 4),
                "suspicion_score": suspicion,
            })
    elif ext in ("txt", "md", "html", "htm"):
        raw = path.read_text(encoding="utf-8", errors="replace")
        zw_count = sum(1 for c in raw if c in (ZW_ONE, ZW_ZERO, "\ufeff"))
        ws_lines = sum(1 for l in raw.splitlines() if l.endswith(" ") or l.endswith("\t"))
        homo_count = sum(1 for c in raw if c in REV_HOMOGLYPH_MAP)
        suspicion = 10
        if zw_count > 0:
            suspicion = max(suspicion, 85)
        if homo_count > 0:
            suspicion = max(suspicion, 80)
        if ws_lines > 5:
            suspicion = max(suspicion, 60)
        report.update({
            "type": "text",
            "zero_width_chars": zw_count,
            "homoglyph_cyrillic_chars": homo_count,
            "trailing_whitespace_lines": ws_lines,
            "suspicion_score": suspicion,
        })
    elif ext in ("zip", "docx", "xlsx", "pptx", "jar"):
        data = path.read_bytes()
        ent = _shannon_entropy(data)
        has_comment = False
        comment_len = 0
        try:
            with zipfile.ZipFile(path, "r") as zf:
                if zf.comment:
                    has_comment = True
                    comment_len = len(zf.comment)
        except Exception:
            pass
        suspicion = 85 if has_comment else (55 if ent > 7.7 else 15)
        report.update({
            "type": "archive",
            "entropy_bits_per_byte": round(ent, 3),
            "zip_comment_found": has_comment,
            "zip_comment_bytes": comment_len,
            "suspicion_score": suspicion,
        })
    else:
        data = path.read_bytes()
        ent = _shannon_entropy(data)
        has_trailer = data.rfind(TRAILER_MAGIC) != -1
        suspicion = 95 if has_trailer else (60 if ent > 7.8 else 20)
        report.update({
            "type": "generic",
            "entropy_bits_per_byte": round(ent, 3),
            "trailer_magic_found": has_trailer,
            "suspicion_score": suspicion,
            "note": "entropy near 8.0 suggests compressed/encrypted data pocket",
        })

    return report


def render_bitplane_ascii(bitplane_channel: np.ndarray, width: int = 48, height: int = 16) -> str:
    """Downsamples a bitplane and renders a 2D ASCII density map."""
    h, w = bitplane_channel.shape
    bh, bw = max(1, h // height), max(1, w // width)
    chars = [" ", "░", "▒", "▓", "█"]
    lines = []
    for y in range(0, min(h, height * bh), bh):
        row = []
        for x in range(0, min(w, width * bw), bw):
            block = bitplane_channel[y:y + bh, x:x + bw]
            density = float(block.mean())
            char_idx = min(len(chars) - 1, int(round(density * (len(chars) - 1))))
            row.append(chars[char_idx])
        lines.append("".join(row))
    return "\n".join(lines)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


# =============================================================================
# Profile Management System (PRD Section 7)
# =============================================================================
DEFAULT_PROFILES = {
    "ctf-quick": {
        "description": "Fast turnaround for CTF competitions (Deflate + AES-256-GCM + Low KDF)",
        "cipher": "aes-256-gcm",
        "compress": "deflate",
        "time_cost": 1,
        "mem_cost_exp": 14,
        "bits": 1,
    },
    "max-stealth": {
        "description": "Maximum stealth (XChaCha20-Poly1305 + Zstd + Argon2 128MB + 1-bit scattered)",
        "cipher": "xchacha20poly1305",
        "compress": "zstd",
        "time_cost": 4,
        "mem_cost_exp": 17,
        "bits": 1,
    },
    "max-capacity": {
        "description": "High payload capacity (4-bit Image LSB + Zstandard level 12)",
        "cipher": "xchacha20poly1305",
        "compress": "zstd",
        "time_cost": 3,
        "mem_cost_exp": 16,
        "bits": 4,
    },
    "watermark": {
        "description": "Provenance watermark profile with verification signature",
        "cipher": "aes-256-gcm",
        "compress": "zstd",
        "time_cost": 2,
        "mem_cost_exp": 15,
        "bits": 1,
    },
    "covert-text": {
        "description": "Stealthy text steganography via Cyrillic/Latin homoglyphs",
        "method": "text.homoglyph",
        "cipher": "xchacha20poly1305",
        "compress": "zstd",
        "bits": 1,
    },
}


def get_profile_dir() -> Path:
    p = Path.home() / ".sleezy" / "profiles"
    p.mkdir(parents=True, exist_ok=True)
    return p


def load_profile(name: str) -> dict:
    if name in DEFAULT_PROFILES:
        return DEFAULT_PROFILES[name]
    custom_path = get_profile_dir() / f"{name}.json"
    if custom_path.exists():
        return json.loads(custom_path.read_text(encoding="utf-8"))
    raise SleezyError(f"Profile '{name}' not found", EXIT_BADARGS)


def do_profile(action: str, name: Optional[str] = None, output: Optional[Path] = None,
               input_file: Optional[Path] = None):
    p_dir = get_profile_dir()
    if action == "list":
        rows = []
        for k, v in DEFAULT_PROFILES.items():
            rows.append([k, "built-in", v.get("description", "")])
        for f in p_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                rows.append([f.stem, "custom", data.get("description", "")])
            except Exception:
                pass
        UI.table(["Profile", "Type", "Description"], rows)
    elif action == "show":
        if not name:
            raise SleezyError("Specify profile name to show", EXIT_BADARGS)
        data = load_profile(name)
        print(json.dumps(data, indent=2))
    elif action == "delete":
        if not name:
            raise SleezyError("Specify profile name to delete", EXIT_BADARGS)
        if name in DEFAULT_PROFILES:
            raise SleezyError("Cannot delete built-in profile", EXIT_BADARGS)
        target = p_dir / f"{name}.json"
        if target.exists():
            target.unlink()
            UI.ok(f"Deleted profile: {name}")
        else:
            raise SleezyError(f"Profile '{name}' not found", EXIT_BADARGS)


# =============================================================================
# Batch Processing Engine (PRD Section 4.6)
# =============================================================================
def do_batch_embed(pattern: str, payload_paths: list[Path], raw_text: Optional[str],
                   passphrase: str, out_dir: Path, method_name: Optional[str] = None):
    out_dir.mkdir(parents=True, exist_ok=True)
    files = glob.glob(pattern)
    if not files:
        raise SleezyError(f"No files matched pattern '{pattern}'", EXIT_BADARGS)

    UI.info(f"Starting batch embed over {len(files)} carriers...")
    results = []
    for idx, fpath in enumerate(files, 1):
        carrier = Path(fpath)
        out_target = out_dir / f"{carrier.stem}_stego{carrier.suffix}"
        try:
            rep = do_embed(
                carrier, out_target, payload_paths, raw_text, passphrase,
                method_name=method_name, quiet=True
            )
            results.append([carrier.name, "SUCCESS", f"{rep['detectability_score']}/100", out_target.name])
            print(f"  [{idx}/{len(files)}] {UI.GREEN}✓{UI.RESET} {carrier.name} -> {out_target.name}")
        except Exception as e:
            results.append([carrier.name, f"FAIL ({e})", "N/A", "N/A"])
            print(f"  [{idx}/{len(files)}] {UI.RED}✗{UI.RESET} {carrier.name}: {e}")

    print()
    UI.table(["Carrier", "Status", "Risk Score", "Output File"], results)


def do_batch_extract(pattern: str, out_dir: Path, passphrase: str, method_name: Optional[str] = None):
    out_dir.mkdir(parents=True, exist_ok=True)
    files = glob.glob(pattern)
    if not files:
        raise SleezyError(f"No files matched pattern '{pattern}'", EXIT_BADARGS)

    UI.info(f"Starting batch extract over {len(files)} files...")
    results = []
    for idx, fpath in enumerate(files, 1):
        stego = Path(fpath)
        sub_out = out_dir / stego.stem
        try:
            rep = do_extract(stego, sub_out, passphrase, method_name=method_name, auto=True, quiet=True)
            results.append([stego.name, "EXTRACTED", rep.get("method", "auto"), str(sub_out)])
            print(f"  [{idx}/{len(files)}] {UI.GREEN}✓{UI.RESET} {stego.name}")
        except Exception as e:
            results.append([stego.name, "FAILED", "N/A", str(e)])
            print(f"  [{idx}/{len(files)}] {UI.RED}✗{UI.RESET} {stego.name}")

    print()
    UI.table(["Stego File", "Status", "Method", "Result Destination"], results)


# =============================================================================
# Interactive Guided Wizard Mode (PRD Section 5.1 & 8.1)
# =============================================================================
def run_wizard():
    """Step-by-step interactive wizard for beginners and guided workflows."""
    UI.print_banner()
    UI.box("SLEEZY INTERACTIVE WIZARD", [
        "Welcome to the guided workflow assistant.",
        "Choose an action below to proceed step-by-step:",
        f"  {UI.BOLD}[1]{UI.RESET} Hide a payload into a cover carrier (Embed)",
        f"  {UI.BOLD}[2]{UI.RESET} Recover hidden payload from a file (Extract)",
        f"  {UI.BOLD}[3]{UI.RESET} Analyze a file for steganography (Analyze)",
    ], color=UI.MAGENTA)

    try:
        choice = input(f"\n{UI.BOLD}Select operation [1-3]:{UI.RESET} ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return

    if choice == "1":
        carrier_str = input(f"{UI.BOLD}Carrier cover file path:{UI.RESET} ").strip().strip("'\"")
        carrier_path = Path(carrier_str)
        if not carrier_path.exists():
            UI.err(f"File not found: {carrier_path}")
            return

        method = pick_method(carrier_path, None)
        UI.ok(f"Carrier loaded: {carrier_path.name} (Suggested method: {method.family}.{method.id})")

        p_type = input(f"\nPayload type ([1] File/Folder, [2] Secret Text message) [1]: ").strip() or "1"
        payload_paths, raw_text = [], None
        if p_type == "2":
            raw_text = input(f"{UI.BOLD}Enter secret text:{UI.RESET} ")
        else:
            p_str = input(f"{UI.BOLD}Payload file or folder path:{UI.RESET} ").strip().strip("'\"")
            payload_paths = [Path(p_str)]
            if not payload_paths[0].exists():
                UI.err("Payload path does not exist.")
                return

        import getpass
        pw = getpass.getpass(f"{UI.BOLD}Passphrase:{UI.RESET} ")
        pw_confirm = getpass.getpass(f"{UI.BOLD}Confirm Passphrase:{UI.RESET} ")
        if pw != pw_confirm:
            UI.err("Passphrases do not match.")
            return

        default_out = carrier_path.with_name(f"{carrier_path.stem}_stego{carrier_path.suffix}")
        out_str = input(f"{UI.BOLD}Output file path [{default_out.name}]:{UI.RESET} ").strip().strip("'\"")
        out_path = Path(out_str) if out_str else default_out

        print(f"\n{UI.CYAN}Processing pipeline...{UI.RESET}")
        try:
            rep = do_embed(carrier_path, out_path, payload_paths, raw_text, pw, quiet=False)
            print()
            UI.ok(f"Stego object successfully generated: {out_path}")
            print(f"{UI.DIM}CLI Equivalent: sleezy embed -c \"{carrier_path}\" "
                  f"{'-t ...' if raw_text else '-p ' + str(payload_paths[0])} -o \"{out_path}\"{UI.RESET}\n")
        except SleezyError as e:
            UI.err(str(e))

    elif choice == "2":
        stego_str = input(f"{UI.BOLD}Stego file path to extract from:{UI.RESET} ").strip().strip("'\"")
        stego_path = Path(stego_str)
        if not stego_path.exists():
            UI.err("File not found.")
            return

        import getpass
        pw = getpass.getpass(f"{UI.BOLD}Passphrase:{UI.RESET} ")
        default_out = Path("./recovered")
        out_str = input(f"{UI.BOLD}Output directory [./recovered]:{UI.RESET} ").strip().strip("'\"")
        out_dir = Path(out_str) if out_str else default_out

        try:
            do_extract(stego_path, out_dir, pw, auto=True, quiet=False)
        except SleezyError as e:
            UI.err(str(e))

    elif choice == "3":
        file_str = input(f"{UI.BOLD}File to inspect:{UI.RESET} ").strip().strip("'\"")
        f_path = Path(file_str)
        if not f_path.exists():
            UI.err("File not found.")
            return
        rep = do_analyze(f_path, deep=True, bitplane=True)
        print()
        UI.box("ANALYSIS RESULTS", [
            f"{UI.CYAN}• File:{UI.RESET}            {rep['file']} ({rep['size']:,} bytes)",
            f"{UI.CYAN}• Type:{UI.RESET}            {rep.get('type')}",
            f"{UI.CYAN}• Suspicion Score:{UI.RESET} {UI.risk_badge(rep['suspicion_score'])}",
            f"{UI.CYAN}• Notes:{UI.RESET}           {rep.get('note', 'No anomalies detected')}",
        ], color=UI.YELLOW)
        if "bitplane_ascii" in rep:
            print(f"\n{UI.BOLD}Bitplane LSB Visual Density:{UI.RESET}")
            print(rep["bitplane_ascii"])


# =============================================================================
# Interactive REPL Shell Engine (PRD Section 5.1 & 5.2)
# =============================================================================
def run_shell():
    """Interactive command-line shell with banner, autocomplete, and history."""
    UI.print_banner()
    UI.print_status_panel()

    print(f"{UI.BOLD}{UI.WHITE}  Type 'wizard' for guided mode, 'help' for commands, or 'exit' to quit.{UI.RESET}\n")

    # Command autocomplete setup
    COMMANDS = ["wizard", "embed", "extract", "analyze", "methods", "formats", "profile", "batch", "verify", "clear", "help", "exit", "quit"]

    if HAVE_READLINE:
        def completer(text, state):
            options = [cmd for cmd in COMMANDS if cmd.startswith(text)]
            if state < len(options):
                return options[state]
            # File completion fallback
            globs = glob.glob(text + "*")
            if state - len(options) < len(globs):
                return globs[state - len(options)]
            return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

    parser = build_parser()

    while True:
        try:
            line = input(f"{UI.BOLD}{UI.CYAN}sleezy{UI.RESET} {UI.PURPLE}❯{UI.RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting Sleezy workbench.")
            break

        if not line:
            continue
        if line in ("exit", "quit", ":q"):
            print("Goodbye.")
            break
        if line in ("clear", "cls"):
            os.system("cls" if os.name == "nt" else "clear")
            continue
        if line == "wizard":
            run_wizard()
            continue

        try:
            args_list = shlex.split(line)
        except Exception as e:
            UI.err(f"Syntax error: {e}")
            continue

        if args_list[0] == "help":
            if len(args_list) > 1:
                try:
                    parser.parse_args([args_list[1], "--help"])
                except SystemExit:
                    pass
            else:
                print_shell_help()
            continue

        try:
            parsed = parser.parse_args(args_list)
            execute_cli_args(parsed)
        except SystemExit:
            pass
        except Exception as e:
            UI.err(str(e))
        print()


def print_shell_help():
    UI.table(["Command", "Description", "Example"], [
        ["wizard", "Guided interactive workflow assistant", "wizard"],
        ["embed", "Hide payload in carrier with encryption & scatter", "embed -c img.png -t 'secret' -o out.png"],
        ["extract", "Recover hidden payload from stego object", "extract -s out.png -o ./recovered"],
        ["analyze", "Steganalysis checks (chi-square, entropy)", "analyze suspicious.png --bitplane"],
        ["methods", "List all available carrier embedding methods", "methods --family image"],
        ["formats", "List supported carrier families", "formats"],
        ["profile", "Manage saved pipeline presets (list/show/new)", "profile list"],
        ["batch", "Batch embed or extract across multiple files", "batch embed --glob 'covers/*.png' -p file.txt"],
        ["verify", "Compute sha256 or verify watermark", "verify file.png"],
        ["clear", "Clear terminal screen", "clear"],
        ["exit", "Exit Sleezy interactive shell", "exit"],
    ])


# =============================================================================
# CLI Parser Setup
# =============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sleezy",
        description="Sleezy - Modular Steganography Workbench & Cryptographic Steganalysis Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=False)

    # Shell
    sub.add_parser("shell", help="Launch interactive command prompt (REPL)")

    # Wizard
    sub.add_parser("wizard", help="Launch guided interactive step-by-step wizard")

    # Embed
    e = sub.add_parser("embed", help="Embed a payload into a carrier")
    e.add_argument("-c", "--carrier", required=True, type=Path, help="Path to cover carrier file")
    e.add_argument("-p", "--payload", nargs="*", type=Path, default=[], help="Payload file(s) or folder")
    e.add_argument("-t", "--text", default=None, help="Secret text message payload")
    e.add_argument("-m", "--method", default=None, help="Embedding method (e.g. image.lsb, text.homoglyph)")
    e.add_argument("--bits", type=int, default=1, choices=[1, 2, 3, 4], help="Bits per channel (image.lsb)")
    e.add_argument("--passphrase", default=None, help="Encryption passphrase (prompted securely if omitted)")
    e.add_argument("--keyfile", type=Path, default=None, help="Optional keyfile to mix into Argon2id KDF")
    e.add_argument("--watermark", default=None, help="Provenance watermark string to encode in container")
    e.add_argument("--cipher", choices=["xchacha20poly1305", "aes-256-gcm"], default="xchacha20poly1305")
    e.add_argument("--compress", choices=["zstd", "deflate", "none"], default="zstd")
    e.add_argument("--profile", default=None, help="Apply preset profile (e.g. ctf-quick, max-stealth)")
    e.add_argument("--dry-run", action="store_true", help="Calculate capacity and risk without writing files")
    e.add_argument("-o", "--output", required=False, type=Path, help="Output destination path")
    e.add_argument("--quiet", action="store_true", help="Quiet output for scripting and CI")

    # Extract
    x = sub.add_parser("extract", help="Extract a payload from a stego object")
    x.add_argument("-s", "--stego", required=True, type=Path, help="Path to stego carrier file")
    x.add_argument("--auto", action="store_true", help="Automatically probe all registered methods")
    x.add_argument("-m", "--method", default=None, help="Specific method to use")
    x.add_argument("--passphrase", default=None, help="Decryption passphrase")
    x.add_argument("--keyfile", type=Path, default=None, help="Keyfile path used during embed")
    x.add_argument("-o", "--output-dir", required=True, type=Path, help="Destination directory for recovered files")
    x.add_argument("--quiet", action="store_true")

    # Analyze
    a = sub.add_parser("analyze", help="Steganalysis (chi-square, entropy, LSB analysis)")
    a.add_argument("file", type=Path, help="Path to file to inspect")
    a.add_argument("--deep", action="store_true", help="Run in-depth heuristic tests")
    a.add_argument("--bitplane", action="store_true", help="Render 2D ASCII bitplane density preview")
    a.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Methods
    m = sub.add_parser("methods", help="List registered carrier methods")
    m.add_argument("--family", default=None, help="Filter by carrier family (image, audio, text, archive, generic)")
    m.add_argument("--json", action="store_true")

    # Formats
    f = sub.add_parser("formats", help="List supported carrier formats")
    f.add_argument("--json", action="store_true")

    # Profile
    pr = sub.add_parser("profile", help="Manage pipeline profiles")
    pr.add_argument("action", choices=["list", "show", "delete"], help="Profile operation")
    pr.add_argument("name", nargs="?", default=None, help="Profile identifier")

    # Batch
    b = sub.add_parser("batch", help="Batch process multiple carriers")
    b_sub = b.add_subparsers(dest="batch_action", required=True)
    be = b_sub.add_parser("embed", help="Batch embed across matching carriers")
    be.add_argument("--glob", required=True, help="Glob pattern for carrier files")
    be.add_argument("-p", "--payload", nargs="*", type=Path, default=[], help="Payload file(s)")
    be.add_argument("-t", "--text", default=None, help="Secret text message")
    be.add_argument("--passphrase", default=None)
    be.add_argument("-m", "--method", default=None)
    be.add_argument("-o", "--output-dir", required=True, type=Path)

    bx = b_sub.add_parser("extract", help="Batch extract across matching carriers")
    bx.add_argument("--glob", required=True, help="Glob pattern for stego files")
    bx.add_argument("--passphrase", default=None)
    bx.add_argument("-m", "--method", default=None)
    bx.add_argument("-o", "--output-dir", required=True, type=Path)

    # Verify
    v = sub.add_parser("verify", help="SHA-256 hash or watermark integrity check")
    v.add_argument("file", type=Path)
    v.add_argument("--hash", default=None, help="Expected SHA-256 hash to compare against")
    v.add_argument("--watermark", action="store_true", help="Inspect and display embedded watermark")

    return p


def _get_passphrase(arg_val: Optional[str]) -> str:
    if arg_val is not None:
        return arg_val
    env_pw = os.environ.get("SLEEZY_PASSPHRASE")
    if env_pw:
        return env_pw
    import getpass
    return getpass.getpass("Passphrase: ")


def execute_cli_args(args: argparse.Namespace) -> int:
    """Executes parsed CLI arguments and returns standard exit code."""
    if args.command == "shell":
        run_shell()
        return EXIT_OK

    if args.command == "wizard":
        run_wizard()
        return EXIT_OK

    if args.command == "embed":
        if not args.text and not args.payload:
            raise SleezyError("Provide --payload and/or --text", EXIT_BADARGS)

        cipher = args.cipher
        compress_algo = args.compress
        bits = args.bits

        if args.profile:
            prof = load_profile(args.profile)
            cipher = prof.get("cipher", cipher)
            compress_algo = prof.get("compress", compress_algo)
            bits = prof.get("bits", bits)
            if "method" in prof and not args.method:
                args.method = prof["method"]

        out_path = args.output or args.carrier.with_name(f"{args.carrier.stem}_stego{args.carrier.suffix}")
        do_embed(
            args.carrier, out_path, args.payload, args.text,
            _get_passphrase(args.passphrase), method_name=args.method,
            cipher=cipher, compress_algo=compress_algo, keyfile=args.keyfile,
            watermark=args.watermark, bits_per_channel=bits,
            dry_run=args.dry_run, quiet=args.quiet
        )
        return EXIT_OK

    if args.command == "extract":
        do_extract(
            args.stego, args.output_dir, _get_passphrase(args.passphrase),
            method_name=args.method, keyfile=args.keyfile,
            auto=args.auto or not args.method, quiet=args.quiet
        )
        return EXIT_OK

    if args.command == "analyze":
        report = do_analyze(args.file, deep=args.deep, bitplane=args.bitplane)
        if args.json or not sys.stdout.isatty():
            print(json.dumps(report, indent=2))
        else:
            UI.box("STEGANALYSIS INSPECTION REPORT", [
                f"{UI.CYAN}• File:{UI.RESET}            {report['file']} ({report['size']:,} bytes)",
                f"{UI.CYAN}• Format Family:{UI.RESET}   {report.get('type')}",
                f"{UI.CYAN}• LSB Deviation:{UI.RESET}   {report.get('lsb_one_ratio', 'N/A')}",
                f"{UI.CYAN}• Chi-Square (χ²):{UI.RESET} {report.get('chi2_statistic', 'N/A')} (p={report.get('chi2_p_value', 'N/A')})",
                f"{UI.CYAN}• Entropy:{UI.RESET}         {report.get('entropy_bits_per_byte', 'N/A')} bits/byte",
                f"{UI.CYAN}• Suspicion Score:{UI.RESET} {UI.risk_badge(report['suspicion_score'])} (\"suspicion_score\": {report['suspicion_score']})",
                f"{UI.CYAN}• Finding:{UI.RESET}         {report.get('note', 'Normal carrier properties')}",
            ], color=UI.CYAN)
            if "bitplane_ascii" in report:
                print(f"\n{UI.BOLD}Bitplane LSB Visual Density:{UI.RESET}")
                print(report["bitplane_ascii"])
        return EXIT_OK

    if args.command == "methods":
        items = [{
            "id": f"{m.family}.{m.id}", "family": m.family, "name": m.display_name,
            "mode": m.mode, "detectability_baseline": m.detectability_baseline,
            "robustness": m.robustness
        } for m in dict.fromkeys(METHODS_BY_ID.values())]
        if args.family:
            items = [i for i in items if i["family"] == args.family]
        if args.json or not sys.stdout.isatty():
            print(json.dumps(items, indent=2))
        else:
            rows = [[i["id"], i["family"], i["name"], i["detectability_baseline"], i["robustness"]] for i in items]
            UI.table(["Method ID", "Family", "Display Name", "Detectability", "Robustness"], rows)
        return EXIT_OK

    if args.command == "formats":
        fams = sorted({m.family for m in METHODS_BY_ID.values()})
        print(json.dumps(fams, indent=2) if args.json else "\n".join(fams))
        return EXIT_OK

    if args.command == "profile":
        do_profile(args.action, args.name)
        return EXIT_OK

    if args.command == "batch":
        if args.batch_action == "embed":
            do_batch_embed(
                args.glob, args.payload, args.text, _get_passphrase(args.passphrase),
                args.output_dir, method_name=args.method
            )
        elif args.batch_action == "extract":
            do_batch_extract(
                args.glob, args.output_dir, _get_passphrase(args.passphrase),
                method_name=args.method
            )
        return EXIT_OK

    if args.command == "verify":
        h = hashlib.sha256(args.file.read_bytes()).hexdigest()
        print(h)
        if args.hash:
            ok = h.lower() == args.hash.lower()
            print("MATCH" if ok else "MISMATCH")
            return EXIT_OK if ok else EXIT_ERR
        return EXIT_OK

    return EXIT_OK


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        # User started script without arguments -> show banner and enter interactive CLI
        if sys.stdin.isatty():
            run_shell()
            return EXIT_OK
        else:
            UI.print_banner()
            parser.print_help()
            return EXIT_OK

    try:
        return execute_cli_args(args)
    except SleezyError as e:
        sys.stderr.write(f"[error] {e}\n")
        return e.code
    except FileNotFoundError as e:
        sys.stderr.write(f"[error] {e}\n")
        return EXIT_ERR
    except Exception as e:
        sys.stderr.write(f"[error] {e}\n")
        return EXIT_ERR


def _first_run_notice():
    marker = Path.home() / ".sleezy" / "first_run_ack"
    if marker.exists():
        return
    sys.stderr.write(
        "Sleezy is a dual-use steganography workbench for privacy, CTFs, research, "
        "watermarking and authorized security testing. No telemetry. All processing "
        "is local. You are responsible for lawful use.\n\n"
    )
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("ack")


if __name__ == "__main__":
    _first_run_notice()
    sys.exit(main())
