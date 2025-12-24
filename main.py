import os
import re
import json
import time
import uuid
import math
import hashlib
import threading
import logging
import urllib.request

from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Callable
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from kivy.lang import Builder
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.uix.widget import Widget
from kivy.metrics import dp
from kivy.graphics import Color, Line, RoundedRectangle, Rectangle
from kivy.properties import NumericProperty, StringProperty, ListProperty, BooleanProperty
from kivy.utils import platform as _kivy_platform
from kivy.animation import Animation

from kivymd.app import MDApp
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton, MDFlatButton, MDIconButton
from kivymd.uix.screen import MDScreen
from kivymd.uix.textfield import MDTextField
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.list import MDList, OneLineListItem
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem

try:
    from kivymd.uix.toolbar import MDTopAppBar as _MDAppBar
    _APPBAR_NAME = "MDTopAppBar"
except Exception:
    from kivymd.uix.toolbar import MDToolbar as _MDAppBar
    _APPBAR_NAME = "MDToolbar"

try:
    from jnius import autoclass
except Exception:
    autoclass = None

# Optional: runtime notification permission helper (Android 13+)
try:
    from android.permissions import request_permissions, Permission  # type: ignore
except Exception:
    request_permissions = None
    Permission = None


# ---------------------------
# YOU MUST SET THESE
# ---------------------------
MODEL_URL = "https://YOUR_HOST/YOUR_MODEL.gguf"  # <- set me
MODEL_SHA256 = "YOUR_64_HEX_SHA256"              # <- set me
MODEL_FILENAME = "medsafe_model.gguf"
CHUNK = 1024 * 1024

# Thread caps (avoid BLAS thread storms)
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

if _kivy_platform != "android" and hasattr(Window, "size"):
    Window.size = (420, 900)


# ---------------------------
# Logging
# ---------------------------
logger = logging.getLogger("medsafe")
logger.setLevel(logging.INFO)


# ---------------------------
# Crypto utils (AES-GCM)
# ---------------------------
def hkdf32(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


def encrypt_bytes_gcm(pt: bytes, key32: bytes) -> bytes:
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key32), modes.GCM(nonce)).encryptor()
    ct = enc.update(pt) + enc.finalize()
    return nonce + ct + enc.tag


def decrypt_bytes_gcm(blob: bytes, key32: bytes) -> bytes:
    if len(blob) < 12 + 16:
        raise ValueError("bad blob")
    nonce = blob[:12]
    tag = blob[-16:]
    ct = blob[12:-16]
    dec = Cipher(algorithms.AES(key32), modes.GCM(nonce, tag)).decryptor()
    return dec.update(ct) + dec.finalize()


def encrypt_file_gcm(src: Path, dst: Path, key32: bytes):
    """
    Stream encrypt: dst format = nonce(12) + ciphertext + tag(16)
    """
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key32), modes.GCM(nonce)).encryptor()
    tmp = dst.with_suffix(dst.suffix + f".tmp.{uuid.uuid4().hex}")
    with src.open("rb") as fin, tmp.open("wb") as fout:
        fout.write(nonce)
        while True:
            buf = fin.read(CHUNK)
            if not buf:
                break
            fout.write(enc.update(buf))
        enc.finalize()
        fout.write(enc.tag)
    tmp.replace(dst)


def decrypt_file_gcm(src: Path, dst: Path, key32: bytes):
    """
    Stream decrypt for files written by encrypt_file_gcm.
    """
    with src.open("rb") as fin:
        nonce = fin.read(12)
        fin.seek(0, os.SEEK_END)
        total = fin.tell()
        if total < 12 + 16:
            raise ValueError("cipher too short")
        tag_pos = total - 16
        fin.seek(tag_pos)
        tag = fin.read(16)
        fin.seek(12)
        dec = Cipher(algorithms.AES(key32), modes.GCM(nonce, tag)).decryptor()
        tmp = dst.with_suffix(dst.suffix + f".tmp.{uuid.uuid4().hex}")
        with tmp.open("wb") as fout:
            remaining = tag_pos - 12
            while remaining > 0:
                n = min(CHUNK, remaining)
                buf = fin.read(n)
                if not buf:
                    break
                remaining -= len(buf)
                fout.write(dec.update(buf))
            dec.finalize()
        tmp.replace(dst)


def _atomic_write(path: Path, data: bytes):
    tmp = path.with_suffix(path.suffix + f".tmp.{uuid.uuid4().hex}")
    tmp.write_bytes(data)
    tmp.replace(path)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------
# Android files dir
# ---------------------------
def _android_files_dir() -> Optional[Path]:
    """
    Stable directory shared between UI app and service: Context.getFilesDir().
    """
    if _kivy_platform != "android" or autoclass is None:
        return None
    try:
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        act = PythonActivity.mActivity
        if act is None:
            return None
        d = act.getFilesDir().getAbsolutePath()
        return Path(str(d))
    except Exception:
        return None


# ---------------------------
# Vault (med schedules + history)
# ---------------------------
class Vault:
    """
    Shared encrypted vault (UI + service read/write in files_dir/medsafe_data).
    File: meds.json.aes
    """
    def __init__(self, files_dir: Path):
        self.base = files_dir / "medsafe_data"
        self.base.mkdir(parents=True, exist_ok=True)
        self.install_master_path = self.base / ".install_master_key"
        self.vault_wrap_path = self.base / ".vault_mdk.wrap"
        self.meds_path = self.base / "meds.json.aes"
        self.lock = threading.Lock()

    def _load_install_master(self) -> Optional[bytes]:
        try:
            if not self.install_master_path.exists():
                return None
            b = self.install_master_path.read_bytes()
            return b[:32] if len(b) >= 32 else None
        except Exception:
            return None

    def _save_install_master(self, k: bytes):
        _atomic_write(self.install_master_path, k)

    def _unwrap_mdk(self) -> bytes:
        master = self._load_install_master()
        if master is None:
            master = os.urandom(32)
            self._save_install_master(master)
            mdk = os.urandom(32)
            _atomic_write(self.vault_wrap_path, encrypt_bytes_gcm(mdk, master))
            return mdk

        if not self.vault_wrap_path.exists():
            mdk = os.urandom(32)
            _atomic_write(self.vault_wrap_path, encrypt_bytes_gcm(mdk, master))
            return mdk

        blob = self.vault_wrap_path.read_bytes()
        try:
            mdk = decrypt_bytes_gcm(blob, master)
        except InvalidTag:
            # corrupted -> reset
            mdk = os.urandom(32)
            _atomic_write(self.vault_wrap_path, encrypt_bytes_gcm(mdk, master))
            return mdk

        if len(mdk) != 32:
            mdk = os.urandom(32)
            _atomic_write(self.vault_wrap_path, encrypt_bytes_gcm(mdk, master))
        return mdk

    def load(self) -> Dict[str, Any]:
        with self.lock:
            mdk = self._unwrap_mdk()
            if not self.meds_path.exists():
                return {"version": 1, "meds": []}
            try:
                blob = self.meds_path.read_bytes()
                pt = decrypt_bytes_gcm(blob, mdk)
                obj = json.loads(pt.decode("utf-8", errors="ignore") or "{}")
                if not isinstance(obj, dict):
                    return {"version": 1, "meds": []}
                obj.setdefault("version", 1)
                obj.setdefault("meds", [])
                return obj
            except Exception:
                return {"version": 1, "meds": []}

    def save(self, obj: Dict[str, Any]):
        with self.lock:
            mdk = self._unwrap_mdk()
            raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            blob = encrypt_bytes_gcm(raw, mdk)
            _atomic_write(self.meds_path, blob)


# ---------------------------
# ModelManager (auto-download + verify + encrypt)
# ---------------------------
class ModelManager:
    """
    First run:
      - downloads plaintext .gguf to models/
      - verifies sha256
      - encrypts to models/<MODEL>.aes with per-install key wrap
      - deletes plaintext

    Runtime:
      - decrypts to tmp plaintext while llama_cpp is loading
      - deletes plaintext after
    """
    def __init__(self, files_dir: Path):
        self.base = files_dir / "medsafe_data"
        self.base.mkdir(parents=True, exist_ok=True)

        self.models_dir = self.base / "models"
        self.models_dir.mkdir(parents=True, exist_ok=True)

        self.tmp_dir = self.base / "tmp"
        self.tmp_dir.mkdir(parents=True, exist_ok=True)

        self.install_master_path = self.base / ".install_master_key"
        self.install_mdk_wrap_path = self.base / ".mdk.wrap.install"

        self.model_enc_path = self.models_dir / (MODEL_FILENAME + ".aes")
        self.model_sha_path = self.models_dir / (MODEL_FILENAME + ".sha256")

        self._lock = threading.Lock()

    def _load_install_master(self) -> Optional[bytes]:
        try:
            if not self.install_master_path.exists():
                return None
            b = self.install_master_path.read_bytes()
            return b[:32] if len(b) >= 32 else None
        except Exception:
            return None

    def _save_install_master(self, k: bytes):
        _atomic_write(self.install_master_path, k)

    def _unwrap_mdk(self) -> bytes:
        master = self._load_install_master()
        if master and self.install_mdk_wrap_path.exists():
            try:
                blob = self.install_mdk_wrap_path.read_bytes()
                mdk = decrypt_bytes_gcm(blob, master)
                if len(mdk) != 32:
                    raise RuntimeError("bad mdk length")
                return mdk
            except Exception:
                try:
                    self.install_mdk_wrap_path.unlink(missing_ok=True)
                except Exception:
                    pass
                try:
                    self.install_master_path.unlink(missing_ok=True)
                except Exception:
                    pass

        mdk = os.urandom(32)
        new_master = os.urandom(32)
        self._save_install_master(new_master)
        wrap = encrypt_bytes_gcm(mdk, new_master)
        _atomic_write(self.install_mdk_wrap_path, wrap)
        logger.info("MODEL: first-run key material created")
        return mdk

    def is_ready(self) -> bool:
        return self.model_enc_path.exists() and self.model_sha_path.exists()

    def _download_to(self, dst: Path, progress_cb: Optional[Callable[[int, int], None]] = None):
        tmp = dst.with_suffix(dst.suffix + f".tmp.{uuid.uuid4().hex}")
        req = urllib.request.Request(MODEL_URL, headers={"User-Agent": "MedSafe/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            got = 0
            with tmp.open("wb") as out:
                while True:
                    buf = resp.read(CHUNK)
                    if not buf:
                        break
                    out.write(buf)
                    got += len(buf)
                    if progress_cb:
                        progress_cb(got, total)
        tmp.replace(dst)

    def ensure_ready(self, progress_cb: Optional[Callable[[int, int], None]] = None):
        """
        Call off-thread. Safe to call multiple times.
        """
        with self._lock:
            if self.is_ready():
                return

            expected = (MODEL_SHA256 or "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise RuntimeError("MODEL_SHA256 not set / invalid")

            if not (MODEL_URL or "").startswith("http"):
                raise RuntimeError("MODEL_URL not set / invalid")

            plain_path = self.models_dir / (MODEL_FILENAME + f".plain.{uuid.uuid4().hex}.gguf")
            try:
                logger.info("MODEL: downloading %s", MODEL_URL)
                self._download_to(plain_path, progress_cb=progress_cb)

                actual = sha256_file(plain_path).lower()
                if actual != expected:
                    raise RuntimeError(f"model sha mismatch: {actual} != {expected}")

                mdk = self._unwrap_mdk()
                logger.info("MODEL: encrypting")
                encrypt_file_gcm(plain_path, self.model_enc_path, mdk)
                _atomic_write(self.model_sha_path, (expected + "\n").encode("utf-8"))
                logger.info("MODEL: ready (encrypted)")
            finally:
                try:
                    plain_path.unlink(missing_ok=True)
                except Exception:
                    pass

    def cleanup_tmp(self):
        try:
            for p in self.tmp_dir.glob("model_plain.*.gguf"):
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
        except Exception:
            pass

    @contextmanager
    def acquire_plain_model(self) -> Path:
        """
        Decrypt encrypted model into tmp plaintext file, yield path, delete after.
        """
        with self._lock:
            if not self.is_ready():
                raise FileNotFoundError("Model not ready")
            expected = (self.model_sha_path.read_text(encoding="utf-8", errors="ignore") or "").strip().split()[0].lower()
            mdk = self._unwrap_mdk()

            plain = self.tmp_dir / f"model_plain.{uuid.uuid4().hex}.gguf"
            decrypt_file_gcm(self.model_enc_path, plain, mdk)

            # verify decrypted sha (guard)
            actual = sha256_file(plain).lower()
            if expected and actual != expected:
                try:
                    plain.unlink(missing_ok=True)
                except Exception:
                    pass
                raise RuntimeError("decrypted model sha mismatch")

        try:
            yield plain
        finally:
            try:
                plain.unlink(missing_ok=True)
            except Exception:
                pass


# ---------------------------
# Risk / schedule logic
# ---------------------------
def _now() -> float:
    return time.time()


def _safe_float(s: str) -> float:
    try:
        return float((s or "").strip())
    except Exception:
        return 0.0


def compute_next_due(med: Dict[str, Any], now_ts: float) -> Optional[float]:
    interval_h = float(med.get("interval_hours") or 0.0)
    if interval_h <= 0.0:
        return None
    last = float(med.get("last_taken_ts") or 0.0)
    if last <= 0.0:
        return now_ts
    return last + interval_h * 3600.0


def due_minutes(med: Dict[str, Any], now_ts: float) -> Optional[float]:
    nd = compute_next_due(med, now_ts)
    if nd is None:
        return None
    return (now_ts - nd) / 60.0  # positive overdue, negative remaining


def due_level(minutes_over: float) -> str:
    if minutes_over < 0:
        return "Low"
    if minutes_over >= 240:
        return "High"
    if minutes_over >= 60:
        return "Medium"
    return "Low"


def dose_safety_level(med: Dict[str, Any], dose_mg: float, now_ts: float) -> Tuple[str, str]:
    """
    Heuristic Low/Medium/High based on:
      - too soon since last dose
      - too much in last 24h relative to max_daily_mg
    """
    interval_h = float(med.get("interval_hours") or 0.0)
    max_daily = float(med.get("max_daily_mg") or 0.0)
    history = list(med.get("history") or [])

    last_taken = float(med.get("last_taken_ts") or 0.0)
    mins_since = (now_ts - last_taken) / 60.0 if last_taken > 0 else 1e9

    cutoff = now_ts - 24 * 3600.0
    total_24h = 0.0
    for item in history:
        try:
            ts = float(item[0])
            mg = float(item[1])
            if ts >= cutoff:
                total_24h += mg
        except Exception:
            continue
    projected = total_24h + max(0.0, float(dose_mg))

    too_soon = (interval_h > 0.0) and (mins_since < interval_h * 60.0 * 0.85)
    way_too_soon = (interval_h > 0.0) and (mins_since < interval_h * 60.0 * 0.60)

    ratio = (projected / max_daily) if max_daily > 0.0 else 0.0

    if way_too_soon or (max_daily > 0.0 and ratio >= 1.05):
        return "High", f"Unsafe: timing/daily limit exceeded (24h total ~{projected:g} mg)."
    if too_soon or (max_daily > 0.0 and ratio >= 0.90):
        return "Medium", f"Caution: close to limits (24h total ~{projected:g} mg)."
    return "Low", f"OK: projected 24h total ~{projected:g} mg."


# ---------------------------
# PUNKD / chunked generation (kept from your style)
# ---------------------------
def _simple_tokenize(text: str) -> List[str]:
    return [t for t in re.findall(r"[A-Za-z0-9_\-]+", (text or "").lower())]


def punkd_analyze(prompt_text: str, top_n: int = 12) -> Dict[str, float]:
    toks = _simple_tokenize(prompt_text)
    freq: Dict[str, float] = {}
    for t in toks:
        freq[t] = freq.get(t, 0.0) + 1.0

    hazard_boost = {
        # dose/risk keywords
        "overdose": 2.0,
        "too": 1.3,
        "soon": 1.6,
        "limit": 1.5,
        "max": 1.4,
        "daily": 1.4,
        "unsafe": 1.8,
        "caution": 1.4,
        "high": 1.2,
        "medium": 1.1,
        "low": 1.1,
    }

    scored: Dict[str, float] = {}
    for t, c in freq.items():
        boost = hazard_boost.get(t, 1.0)
        scored[t] = c * boost

    items = sorted(scored.items(), key=lambda x: -x[1])[:top_n]
    if not items:
        return {}
    maxv = items[0][1]
    return {k: float(v / maxv) for k, v in items}


def punkd_apply(prompt_text: str, token_weights: Dict[str, float], profile: str = "balanced") -> Tuple[str, float]:
    if not token_weights:
        return prompt_text, 1.0
    mean_weight = sum(token_weights.values()) / len(token_weights)
    profile_map = {"conservative": 0.7, "balanced": 1.0, "aggressive": 1.3}
    base = profile_map.get(profile, 1.0)
    multiplier = 1.0 + (mean_weight - 0.5) * 0.8 * (base if base > 1.0 else 1.0)
    multiplier = max(0.6, min(1.8, multiplier))
    sorted_tokens = sorted(token_weights.items(), key=lambda x: -x[1])[:6]
    markers = " ".join([f"<ATTN:{t}:{round(w,2)}>" for t, w in sorted_tokens])
    patched = prompt_text + "\n\n[PUNKD_MARKERS] " + markers
    return patched, multiplier


def chunked_generate(
    llm,
    prompt: str,
    max_total_tokens: int = 64,
    chunk_tokens: int = 16,
    base_temperature: float = 0.10,
    punkd_profile: str = "conservative",
    streaming_callback: Optional[Callable[[str], None]] = None,
) -> str:
    assembled = ""
    cur_prompt = prompt
    token_weights = punkd_analyze(prompt, top_n=16)
    iterations = max(1, (max_total_tokens + chunk_tokens - 1) // chunk_tokens)
    prev_tail = ""
    for _ in range(iterations):
        patched_prompt, mult = punkd_apply(cur_prompt, token_weights, profile=punkd_profile)
        temp = max(0.01, min(2.0, base_temperature * mult))
        out = llm(patched_prompt, max_tokens=chunk_tokens, temperature=temp)

        text = ""
        if isinstance(out, dict):
            try:
                text = out.get("choices", [{"text": ""}])[0].get("text", "")
            except Exception:
                text = out.get("text", "")
        else:
            text = str(out or "")

        text = (text or "").strip()
        if not text:
            break

        overlap = 0
        max_ol = min(30, len(prev_tail), len(text))
        for olen in range(max_ol, 0, -1):
            if prev_tail.endswith(text[:olen]):
                overlap = olen
                break
        append_text = text[overlap:] if overlap else text
        assembled += append_text
        prev_tail = assembled[-120:] if len(assembled) > 120 else assembled

        if streaming_callback:
            streaming_callback(append_text)

        m = re.search(r"\b(Low|Medium|High)\b", assembled, re.IGNORECASE)
        if m:
            break

        if len(text.split()) < max(4, chunk_tokens // 8):
            break

        cur_prompt = prompt + "\n\nAssistant so far:\n" + assembled + "\n\nContinue:"
    return assembled.strip()


# ---------------------------
# llama_cpp inference for med risk
# ---------------------------
def load_llama(model_path: Path):
    from llama_cpp import Llama  # type: ignore
    try:
        c = os.cpu_count() or 1
    except Exception:
        c = 1
    threads = 2 if c >= 2 else 1
    return Llama(
        model_path=str(model_path),
        n_ctx=768,
        n_threads=threads,
        n_batch=64,
        use_mmap=False,
        use_mlock=False,
        n_gpu_layers=0,
        verbose=False,
    )


def build_med_risk_prompt(med: Dict[str, Any], dose_mg: float, now_ts: float) -> str:
    name = str(med.get("name") or "Medication")
    interval_h = float(med.get("interval_hours") or 0.0)
    max_daily = float(med.get("max_daily_mg") or 0.0)
    last = float(med.get("last_taken_ts") or 0.0)
    mins_since = (now_ts - last) / 60.0 if last > 0 else 999999.0

    cutoff = now_ts - 24 * 3600.0
    hist = list(med.get("history") or [])
    total_24h = 0.0
    for item in hist:
        try:
            ts = float(item[0]); mg = float(item[1])
            if ts >= cutoff:
                total_24h += mg
        except Exception:
            continue
    projected = total_24h + max(0.0, float(dose_mg))

    return (
        "ROLE\n"
        "You are a medication reminder safety classifier.\n"
        "Return ONLY one word: Low, Medium, or High.\n\n"
        "RULES\n"
        "- Output exactly one word: Low or Medium or High.\n"
        "- Be conservative if uncertain.\n"
        "- High if dose is too soon or exceeds daily max.\n"
        "- Medium if close to interval or close to daily max.\n"
        "- Low otherwise.\n\n"
        "DATA\n"
        f"med_name: {name}\n"
        f"dose_mg: {dose_mg}\n"
        f"interval_hours: {interval_h}\n"
        f"minutes_since_last_dose: {mins_since:.1f}\n"
        f"max_daily_mg: {max_daily}\n"
        f"total_last_24h_mg: {total_24h:.1f}\n"
        f"projected_24h_total_mg_if_taken: {projected:.1f}\n\n"
        "OUTPUT\n"
        "Low | Medium | High\n"
    )


def run_med_scan_blocking(model_mgr: ModelManager, med: Dict[str, Any], dose_mg: float) -> Tuple[str, str]:
    now_ts = _now()
    if not model_mgr.is_ready():
        lvl, msg = dose_safety_level(med, dose_mg, now_ts)
        return lvl, f"[fallback] {msg}"

    prompt = build_med_risk_prompt(med, dose_mg, now_ts)
    out_text = ""

    with model_mgr.acquire_plain_model() as mp:
        llm = load_llama(mp)
        try:
            out_text = chunked_generate(
                llm,
                prompt,
                max_total_tokens=48,
                chunk_tokens=16,
                base_temperature=0.10,
                punkd_profile="conservative",
            )
        finally:
            try:
                llm.close()
            except Exception:
                pass

    m = re.search(r"\b(low|medium|high)\b", out_text, re.IGNORECASE)
    label = m.group(1).capitalize() if m else ""
    if label not in ("Low", "Medium", "High"):
        lvl, msg = dose_safety_level(med, dose_mg, now_ts)
        return lvl, f"[fallback] {msg} / raw={out_text[:120]}"
    return label, out_text.strip()


# ---------------------------
# UI widgets (wheel + cards)
# ---------------------------
class BackgroundGradient(Widget):
    top_color = ListProperty([0.08, 0.10, 0.16, 1])
    bottom_color = ListProperty([0.02, 0.03, 0.05, 1])
    steps = NumericProperty(56)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, top_color=self._redraw, bottom_color=self._redraw, steps=self._redraw)

    def _lerp(self, a, b, t):
        return a + (b - a) * t

    def _redraw(self, *args):
        self.canvas.before.clear()
        x, y = self.pos
        w, h = self.size
        n = max(10, int(self.steps))
        with self.canvas.before:
            for i in range(n):
                t = i / (n - 1)
                r = self._lerp(self.top_color[0], self.bottom_color[0], t)
                g = self._lerp(self.top_color[1], self.bottom_color[1], t)
                b = self._lerp(self.top_color[2], self.bottom_color[2], t)
                a = self._lerp(self.top_color[3], self.bottom_color[3], t)
                Color(r, g, b, a)
                Rectangle(pos=(x, y + (h * i / n)), size=(w, h / n + 1))


class GlassCard(Widget):
    radius = NumericProperty(dp(28))
    fill = ListProperty([1, 1, 1, 0.06])
    border = ListProperty([1, 1, 1, 0.14])
    highlight = ListProperty([1, 1, 1, 0.09])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, radius=self._redraw, fill=self._redraw, border=self._redraw, highlight=self._redraw)

    def _redraw(self, *args):
        self.canvas.clear()
        x, y = self.pos
        w, h = self.size
        r = float(self.radius)
        with self.canvas:
            Color(0, 0, 0, 0.26)
            RoundedRectangle(pos=(x, y - dp(2)), size=(w, h + dp(4)), radius=[r])
            Color(*self.fill)
            RoundedRectangle(pos=(x, y), size=(w, h), radius=[r])
            Color(*self.highlight)
            RoundedRectangle(pos=(x + dp(1), y + h * 0.55), size=(w - dp(2), h * 0.45), radius=[r])
            Color(*self.border)
            Line(rounded_rectangle=[x, y, w, h, r], width=dp(1.15))


class StatusPill(Widget):
    text = StringProperty("Neutral")
    tone = StringProperty("neutral")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, text=self._redraw, tone=self._redraw)

    def _tone_rgba(self):
        if self.tone == "good":
            return (0.10, 0.90, 0.42, 0.22)
        if self.tone == "warn":
            return (0.98, 0.78, 0.20, 0.22)
        if self.tone == "bad":
            return (0.98, 0.22, 0.30, 0.22)
        return (1, 1, 1, 0.10)

    def _tone_line(self):
        if self.tone == "good":
            return (0.10, 0.90, 0.42, 0.30)
        if self.tone == "warn":
            return (0.98, 0.78, 0.20, 0.30)
        if self.tone == "bad":
            return (0.98, 0.22, 0.30, 0.30)
        return (1, 1, 1, 0.16)

    def _redraw(self, *args):
        self.canvas.clear()
        x, y = self.pos
        w, h = self.size
        r = min(h / 2.0, dp(16))
        bg = self._tone_rgba()
        ln = self._tone_line()
        with self.canvas:
            Color(0, 0, 0, 0.18)
            RoundedRectangle(pos=(x, y - dp(1.5)), size=(w, h + dp(3)), radius=[r])
            Color(*bg)
            RoundedRectangle(pos=(x, y), size=(w, h), radius=[r])
            Color(*ln)
            Line(rounded_rectangle=[x, y, w, h, r], width=dp(1.1))


class RiskWheelNeo(Widget):
    value = NumericProperty(0.5)
    level = StringProperty("NEUTRAL")
    animated = BooleanProperty(True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, value=self._redraw, level=self._redraw)

    def set_level(self, level: str, animate: bool = True):
        lvl = (level or "").strip().upper()
        if lvl == "LOW":
            target_level, target_value = "LOW", 0.0
        elif lvl == "MEDIUM":
            target_level, target_value = "MEDIUM", 0.5
        elif lvl == "HIGH":
            target_level, target_value = "HIGH", 1.0
        else:
            target_level, target_value = "NEUTRAL", 0.5
        self.level = target_level
        if animate and self.animated:
            Animation.cancel_all(self, "value")
            Animation(value=float(target_value), d=0.35, t="out_cubic").start(self)
        else:
            self.value = float(target_value)

    def _level_color(self):
        if self.level == "LOW":
            return (0.10, 0.90, 0.42)
        if self.level == "HIGH":
            return (0.98, 0.22, 0.30)
        if self.level == "MEDIUM":
            return (0.98, 0.78, 0.20)
        return (0.78, 0.82, 0.90)

    def _seg_alpha(self):
        return 0.58 if self.level == "NEUTRAL" else 0.80

    def _redraw(self, *args):
        self.canvas.clear()
        cx, cy = self.center
        r = min(self.width, self.height) * 0.41
        thickness = max(dp(12), r * 0.16)
        ang = -135.0 + 270.0 * float(self.value)
        ang_rad = math.radians(ang)
        active_rgb = self._level_color()
        seg_a = self._seg_alpha()
        segs = [
            ((0.10, 0.85, 0.40), -135.0, -45.0),
            ((0.98, 0.78, 0.20), -45.0, 45.0),
            ((0.98, 0.22, 0.30), 45.0, 135.0),
        ]
        gap = 6.0
        with self.canvas:
            Color(1, 1, 1, 0.06)
            Line(circle=(cx, cy, r + dp(10), -140, 140), width=dp(1.2))
            Color(0.10, 0.12, 0.18, 0.62)
            Line(circle=(cx, cy, r, -140, 140), width=thickness, cap="round")
            for rgb, a0, a1 in segs:
                a0g = a0 + gap / 2.0
                a1g = a1 - gap / 2.0
                Color(rgb[0], rgb[1], rgb[2], seg_a)
                Line(circle=(cx, cy, r, a0g, a1g), width=thickness, cap="round")
            nx = cx + math.cos(ang_rad) * (r * 0.92)
            ny = cy + math.sin(ang_rad) * (r * 0.92)
            Color(active_rgb[0], active_rgb[1], active_rgb[2], 0.24)
            Line(points=[cx, cy, nx, ny], width=max(dp(3.2), thickness * 0.16), cap="round")
            Color(0.97, 0.97, 0.99, 0.98)
            Line(points=[cx, cy, nx, ny], width=max(dp(2.0), thickness * 0.10), cap="round")
            Color(1, 1, 1, 0.085)
            RoundedRectangle(pos=(cx - dp(18), cy - dp(18)), size=(dp(36), dp(36)), radius=[dp(18)])
            Color(1, 1, 1, 0.18)
            Line(rounded_rectangle=[cx - dp(18), cy - dp(18), dp(36), dp(36), dp(18)], width=dp(1.0))
            Color(0.06, 0.07, 0.10, 0.92)
            RoundedRectangle(pos=(cx - dp(12), cy - dp(12)), size=(dp(24), dp(24)), radius=[dp(12)])


# ---------------------------
# KV
# ---------------------------
KV_TEMPLATE = r"""
#:import dp kivy.metrics.dp

<BackgroundGradient>:
    size_hint: 1, 1

<RiskWheelNeo>:
    size_hint: None, None

<StatusPill>:
    size_hint: None, None

MDScreen:
    MDBoxLayout:
        orientation: "vertical"
        padding: 0, app.safe_top, 0, 0
        spacing: "0dp"

        APPBAR_WIDGET:
            title: "MedSafe"
            elevation: 8
            right_action_items: [["bell-outline", lambda x: app.request_notif_permission()],
                                 ["refresh", lambda x: app.refresh_meds()]]

        ScreenManager:
            id: screen_manager
            size_hint_y: 1

            MDScreen:
                name: "meds"
                BackgroundGradient:
                    top_color: 0.08, 0.10, 0.16, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                ScrollView:
                    do_scroll_x: False

                    MDBoxLayout:
                        orientation: "vertical"
                        padding: "16dp"
                        spacing: "16dp"
                        adaptive_height: True

                        FloatLayout:
                            size_hint_y: None
                            height: header_body.minimum_height + dp(34)

                            GlassCard:
                                pos: self.pos
                                size: self.size
                                radius: dp(28)

                            MDBoxLayout:
                                id: header_body
                                orientation: "vertical"
                                size_hint: 1, None
                                height: self.minimum_height
                                pos: self.parent.pos
                                padding: "18dp"
                                spacing: "12dp"

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "34dp"
                                    spacing: "10dp"

                                    MDLabel:
                                        text: "Dose Safety / Reminder Risk"
                                        bold: True
                                        font_style: "H6"
                                        halign: "left"
                                        valign: "middle"

                                    Widget:

                                    FloatLayout:
                                        size_hint: None, None
                                        size: "118dp", "30dp"
                                        StatusPill:
                                            id: status_pill
                                            pos: self.pos
                                            size: self.size
                                        MDLabel:
                                            id: status_pill_text
                                            text: "Neutral"
                                            halign: "center"
                                            valign: "middle"
                                            size_hint: 1, 1
                                            pos: self.pos
                                            theme_text_color: "Custom"
                                            text_color: 0.92, 0.94, 0.98, 0.92

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "244dp"
                                    padding: "0dp"
                                    RiskWheelNeo:
                                        id: risk_wheel
                                        size: "224dp", "224dp"
                                        pos_hint: {"center_x": 0.5, "center_y": 0.52}

                                MDLabel:
                                    id: risk_text
                                    text: "RISK: —"
                                    halign: "center"
                                    size_hint_y: None
                                    height: "24dp"
                                    theme_text_color: "Custom"
                                    text_color: 0.90, 0.92, 0.96, 0.95

                                MDLabel:
                                    id: selected_text
                                    text: "Selected: —"
                                    halign: "center"
                                    size_hint_y: None
                                    height: "22dp"
                                    theme_text_color: "Secondary"

                        FloatLayout:
                            size_hint_y: None
                            height: form_body.minimum_height + dp(34)

                            GlassCard:
                                pos: self.pos
                                size: self.size
                                radius: dp(28)
                                fill: 1, 1, 1, 0.045
                                border: 1, 1, 1, 0.11
                                highlight: 1, 1, 1, 0.07

                            MDBoxLayout:
                                id: form_body
                                orientation: "vertical"
                                size_hint: 1, None
                                height: self.minimum_height
                                pos: self.parent.pos
                                padding: "18dp"
                                spacing: "10dp"

                                MDTextField:
                                    id: med_name
                                    hint_text: "Medication name"
                                    mode: "fill"

                                MDTextField:
                                    id: dose_mg
                                    hint_text: "Dose (mg) e.g. 200"
                                    mode: "fill"
                                    input_filter: "float"

                                MDTextField:
                                    id: interval_h
                                    hint_text: "Interval hours e.g. 8"
                                    mode: "fill"
                                    input_filter: "float"

                                MDTextField:
                                    id: max_daily
                                    hint_text: "Max daily mg (optional) e.g. 1200"
                                    mode: "fill"
                                    input_filter: "float"

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "46dp"
                                    spacing: "10dp"

                                    MDRaisedButton:
                                        text: "Save / Update"
                                        size_hint_x: 1
                                        on_release: app.on_save_med()

                                    MDRaisedButton:
                                        text: "Log Dose Now"
                                        size_hint_x: 1
                                        on_release: app.on_log_dose()

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "46dp"
                                    spacing: "10dp"

                                    MDFlatButton:
                                        text: "Delete"
                                        on_release: app.on_delete_med()

                                    Widget:

                                    MDRaisedButton:
                                        text: "Start Background Reminders"
                                        on_release: app.start_bg_service()

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "46dp"
                                    spacing: "10dp"

                                    MDRaisedButton:
                                        text: "Stop Background Reminders"
                                        on_release: app.stop_bg_service()

                                    Widget:

                                    MDFlatButton:
                                        text: "Refresh"
                                        on_release: app.refresh_meds()

                                MDLabel:
                                    id: action_result
                                    text: ""
                                    halign: "center"
                                    size_hint_y: None
                                    height: "42dp"
                                    theme_text_color: "Secondary"
                                    text_size: self.width, None
                                    valign: "middle"

                        FloatLayout:
                            size_hint_y: None
                            height: list_body.minimum_height + dp(34)

                            GlassCard:
                                pos: self.pos
                                size: self.size
                                radius: dp(28)

                            MDBoxLayout:
                                id: list_body
                                orientation: "vertical"
                                size_hint: 1, None
                                height: self.minimum_height
                                pos: self.parent.pos
                                padding: "18dp"
                                spacing: "10dp"
                                adaptive_height: True

                                MDLabel:
                                    text: "Medications"
                                    bold: True
                                    font_style: "Subtitle1"
                                    halign: "left"
                                    theme_text_color: "Custom"
                                    text_color: 0.90, 0.92, 0.96, 0.95
                                    size_hint_y: None
                                    height: "22dp"

                                ScrollView:
                                    size_hint_y: None
                                    height: "260dp"
                                    do_scroll_x: False

                                    MDList:
                                        id: med_list

            MDScreen:
                name: "debug"
                BackgroundGradient:
                    top_color: 0.06, 0.08, 0.13, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                ScrollView:
                    do_scroll_x: False
                    MDBoxLayout:
                        orientation: "vertical"
                        padding: "14dp"
                        spacing: "10dp"
                        adaptive_height: True

                        GlassCard:
                            size_hint_y: None
                            height: debug_text.texture_size[1] + dp(40)
                            radius: dp(28)

                        MDLabel:
                            id: debug_text
                            text: ""
                            theme_text_color: "Secondary"
                            halign: "left"
                            markup: False
                            text_size: self.width, None
                            size_hint_y: None
                            height: self.texture_size[1] + dp(20)

        MDBottomNavigation:
            id: bottom_nav
            size_hint_y: None
            height: "72dp"

            MDBottomNavigationItem:
                name: "nav_meds"
                text: "Meds"
                icon: "pill"
                on_tab_press: app.switch_screen("meds")

            MDBottomNavigationItem:
                name: "nav_debug"
                text: "Debug"
                icon: "bug-outline"
                on_tab_press: app.switch_screen("debug")
"""
KV = KV_TEMPLATE.replace("APPBAR_WIDGET", _APPBAR_NAME)


# ---------------------------
# App
# ---------------------------
class MedSafeApp(MDApp):
    safe_top = NumericProperty(0)

    _exec: Optional[ThreadPoolExecutor] = None
    _selected_med_id: Optional[str] = None

    _files_dir: Optional[Path] = None
    _vault: Optional[Vault] = None
    _model_mgr: Optional[ModelManager] = None

    def build(self):
        self.title = "MedSafe"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Blue"
        self.safe_top = dp(24) if _kivy_platform == "android" else 0

        self._exec = ThreadPoolExecutor(max_workers=1)

        if _kivy_platform == "android":
            self._files_dir = _android_files_dir()
            if self._files_dir is None:
                # fallback: user_data_dir on some stacks
                self._files_dir = Path(self.user_data_dir)
        else:
            self._files_dir = Path.home() / ".medsafe_files"
            self._files_dir.mkdir(parents=True, exist_ok=True)

        self._vault = Vault(self._files_dir)
        self._model_mgr = ModelManager(self._files_dir)
        self._model_mgr.cleanup_tmp()

        root = Builder.load_string(KV)
        Clock.schedule_once(lambda dt: self.refresh_meds(), 0.1)
        Clock.schedule_once(lambda dt: self._kick_model_download(), 0.2)
        return root

    def on_stop(self):
        try:
            if self._exec:
                self._exec.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    # ---- UI helpers ----
    def _pill(self, tone: str, text: str):
        try:
            scr = self.root.ids.screen_manager.get_screen("meds")
            scr.ids.status_pill.tone = tone
            scr.ids.status_pill_text.text = text
        except Exception:
            pass

    def _set_risk_ui(self, lvl: str):
        try:
            scr = self.root.ids.screen_manager.get_screen("meds")
            scr.ids.risk_wheel.set_level(lvl, animate=True)
            scr.ids.risk_text.text = "RISK: —" if (lvl or "").lower() == "neutral" else f"RISK: {lvl.upper()}"
        except Exception:
            pass

    def request_notif_permission(self):
        if request_permissions is None or Permission is None:
            return
        try:
            request_permissions([Permission.POST_NOTIFICATIONS])
        except Exception:
            pass

    def switch_screen(self, name: str):
        try:
            self.root.ids.screen_manager.current = name
        except Exception:
            pass
        if name == "debug":
            self.render_debug()

    def render_debug(self):
        try:
            v = self._vault
            mm = self._model_mgr
            if not v or not mm:
                self.root.ids.debug_text.text = "not ready"
                return
            self.root.ids.debug_text.text = (
                f"platform: {_kivy_platform}\n"
                f"files_dir: {self._files_dir}\n"
                f"vault_dir: {v.base}\n"
                f"meds_file: {v.meds_path} (exists={v.meds_path.exists()})\n"
                f"model_enc: {mm.model_enc_path} (exists={mm.model_enc_path.exists()})\n"
                f"model_sha: {mm.model_sha_path} (exists={mm.model_sha_path.exists()})\n"
                f"selected_med_id: {self._selected_med_id}\n"
            )
        except Exception:
            pass

    # ---- Model auto-download ----
    def _kick_model_download(self):
        if not self._exec or not self._model_mgr:
            return
        if self._model_mgr.is_ready():
            self._pill("good", "Ready")
            self._set_risk_ui("Neutral")
            try:
                scr = self.root.ids.screen_manager.get_screen("meds")
                scr.ids.action_result.text = "Model ready (offline)."
            except Exception:
                pass
            return

        self._pill("warn", "Working")
        try:
            scr = self.root.ids.screen_manager.get_screen("meds")
            scr.ids.action_result.text = "Checking/downloading model…"
        except Exception:
            pass

        fut = self._exec.submit(self._ensure_model_ready_bg)
        fut.add_done_callback(lambda f: Clock.schedule_once(lambda dt: self._model_done_ui(f), 0))

    def _ensure_model_ready_bg(self):
        assert self._model_mgr is not None

        def progress(got: int, total: int):
            if total > 0:
                pct = int((got / max(1, total)) * 100)
                Clock.schedule_once(lambda dt: self._model_progress_ui(f"Downloading model… {pct}%"), 0)
            else:
                Clock.schedule_once(lambda dt: self._model_progress_ui(f"Downloading model… {got//1024//1024}MB"), 0)

        self._model_mgr.ensure_ready(progress_cb=progress)
        return True

    def _model_progress_ui(self, text: str):
        try:
            scr = self.root.ids.screen_manager.get_screen("meds")
            scr.ids.action_result.text = text
        except Exception:
            pass

    def _model_done_ui(self, fut):
        try:
            fut.result()
            self._pill("good", "Ready")
            try:
                scr = self.root.ids.screen_manager.get_screen("meds")
                scr.ids.action_result.text = "Model ready (offline)."
            except Exception:
                pass
        except Exception as e:
            self._pill("bad", "Model Err")
            try:
                scr = self.root.ids.screen_manager.get_screen("meds")
                scr.ids.action_result.text = f"Model download failed: {e}"
            except Exception:
                pass

    # ---- Med list refresh ----
    def refresh_meds(self):
        if not self._exec or not self._vault:
            return
        fut = self._exec.submit(self._vault.load)
        fut.add_done_callback(lambda f: Clock.schedule_once(lambda dt: self._refresh_ui_from_vault(f), 0))

    def _refresh_ui_from_vault(self, fut):
        try:
            data = fut.result()
        except Exception:
            data = {"version": 1, "meds": []}

        meds = list(data.get("meds") or [])
        now_ts = _now()

        try:
            scr = self.root.ids.screen_manager.get_screen("meds")
            scr.ids.med_list.clear_widgets()

            def _sort_key(m):
                dm = due_minutes(m, now_ts)
                if dm is None:
                    return (999999, 999999)
                # overdue first (bigger dm first)
                return (0, -dm) if dm >= 0 else (1, abs(dm))

            meds_sorted = sorted(meds, key=_sort_key)

            for med in meds_sorted:
                mid = str(med.get("id") or "")
                name = str(med.get("name") or "Medication")
                dm = due_minutes(med, now_ts)
                if dm is None:
                    status = "No schedule"
                else:
                    if dm >= 0:
                        status = f"Due ({due_level(dm)}) • overdue {int(dm)} min"
                    else:
                        status = f"Next in {int(abs(dm))} min"

                item = OneLineListItem(
                    text=f"{name} — {status}",
                    on_release=(lambda _x, _mid=mid: self.select_med(_mid)),
                )
                scr.ids.med_list.add_widget(item)

            # keep selection valid
            if self._selected_med_id and not any(str(m.get("id")) == self._selected_med_id for m in meds):
                self._selected_med_id = None

            self._render_selected(data)
        except Exception:
            pass

    def _render_selected(self, data: Dict[str, Any]):
        scr = self.root.ids.screen_manager.get_screen("meds")
        meds = list(data.get("meds") or [])
        sel = None
        if self._selected_med_id:
            for m in meds:
                if str(m.get("id") or "") == self._selected_med_id:
                    sel = m
                    break

        if not sel:
            scr.ids.selected_text.text = "Selected: —"
            return

        scr.ids.selected_text.text = f"Selected: {sel.get('name','—')}"
        scr.ids.med_name.text = str(sel.get("name") or "")
        scr.ids.dose_mg.text = str(sel.get("dose_mg") or "")
        scr.ids.interval_h.text = str(sel.get("interval_hours") or "")
        scr.ids.max_daily.text = str(sel.get("max_daily_mg") or "")

    def select_med(self, med_id: str):
        self._selected_med_id = med_id
        self.refresh_meds()

    # ---- Save / Delete / Log dose ----
    def on_save_med(self):
        if not self._vault or not self._exec:
            return
        scr = self.root.ids.screen_manager.get_screen("meds")

        name = (scr.ids.med_name.text or "").strip()
        dose = _safe_float(scr.ids.dose_mg.text)
        interval_h = _safe_float(scr.ids.interval_h.text)
        max_daily = _safe_float(scr.ids.max_daily.text)

        if not name:
            scr.ids.action_result.text = "Enter a medication name."
            return

        def job():
            data = self._vault.load()
            meds = list(data.get("meds") or [])

            if self._selected_med_id:
                for m in meds:
                    if str(m.get("id") or "") == self._selected_med_id:
                        m["name"] = name
                        m["dose_mg"] = dose
                        m["interval_hours"] = interval_h
                        m["max_daily_mg"] = max_daily
                        break
                else:
                    self._selected_med_id = None

            if not self._selected_med_id:
                mid = uuid.uuid4().hex[:12]
                meds.append({
                    "id": mid,
                    "name": name,
                    "dose_mg": dose,
                    "interval_hours": interval_h,
                    "max_daily_mg": max_daily,
                    "last_taken_ts": 0.0,
                    "history": [],
                })
                self._selected_med_id = mid

            data["meds"] = meds
            self._vault.save(data)
            return True

        fut = self._exec.submit(job)
        fut.add_done_callback(lambda f: Clock.schedule_once(lambda dt: self._save_done(f), 0))

    def _save_done(self, fut):
        scr = self.root.ids.screen_manager.get_screen("meds")
        try:
            fut.result()
            scr.ids.action_result.text = "Saved."
        except Exception as e:
            scr.ids.action_result.text = f"Save failed: {e}"
        self.refresh_meds()

    def on_delete_med(self):
        if not self._selected_med_id or not self._vault or not self._exec:
            return
        mid = self._selected_med_id

        def job():
            data = self._vault.load()
            meds = [m for m in (data.get("meds") or []) if str(m.get("id") or "") != mid]
            data["meds"] = meds
            self._vault.save(data)
            return True

        fut = self._exec.submit(job)
        fut.add_done_callback(lambda f: Clock.schedule_once(lambda dt: self._delete_done(f), 0))

    def _delete_done(self, fut):
        scr = self.root.ids.screen_manager.get_screen("meds")
        try:
            fut.result()
            scr.ids.action_result.text = "Deleted."
            self._selected_med_id = None
        except Exception as e:
            scr.ids.action_result.text = f"Delete failed: {e}"
        self.refresh_meds()

    def on_log_dose(self):
        if not self._selected_med_id or not self._vault or not self._exec:
            return
        if not self._model_mgr:
            return

        scr = self.root.ids.screen_manager.get_screen("meds")
        dose_override = _safe_float(scr.ids.dose_mg.text)  # allow override per log

        self._pill("warn", "Working")
        scr.ids.action_result.text = "Checking dose…"

        def job():
            data = self._vault.load()
            meds = list(data.get("meds") or [])
            now_ts = _now()

            for m in meds:
                if str(m.get("id") or "") == self._selected_med_id:
                    dose_mg = float(dose_override or m.get("dose_mg") or 0.0)

                    # LLM label (strict) with fallback
                    lvl, raw = run_med_scan_blocking(self._model_mgr, m, dose_mg)

                    # Always log dose after assessment.
                    # If you want to BLOCK logging when lvl=="High", add:
                    #   if lvl == "High": return (lvl, raw, False)
                    hist = list(m.get("history") or [])
                    hist.append([now_ts, dose_mg])
                    m["history"] = hist[-300:]
                    m["last_taken_ts"] = now_ts
                    if dose_override:
                        m["dose_mg"] = dose_override

                    data["meds"] = meds
                    self._vault.save(data)
                    return (lvl, raw, True)

            return ("Medium", "Selection missing.", False)

        fut = self._exec.submit(job)
        fut.add_done_callback(lambda f: Clock.schedule_once(lambda dt: self._log_done(f), 0))

    def _log_done(self, fut):
        scr = self.root.ids.screen_manager.get_screen("meds")
        try:
            lvl, raw, did = fut.result()
        except Exception as e:
            lvl, raw, did = ("High", f"Log failed: {e}", False)

        lvl_u = (lvl or "").strip().capitalize()
        if lvl_u not in ("Low", "Medium", "High"):
            lvl_u = "Neutral"

        self._set_risk_ui(lvl_u)

        if lvl_u == "Low":
            self._pill("good", "Low")
        elif lvl_u == "Medium":
            self._pill("warn", "Medium")
        elif lvl_u == "High":
            self._pill("bad", "High")
        else:
            self._pill("neutral", "Neutral")

        # Show a short message
        scr.ids.action_result.text = raw[:220] if raw else ("Logged." if did else "No change.")
        self.refresh_meds()

    # ---- Android background service start/stop ----
    def _service_class(self) -> Optional[Any]:
        """
        For buildozer.spec: services = medservice:service/med_service.py:foreground:sticky
        p4a generates a class: <package>.ServiceMedservice
        """
        if _kivy_platform != "android" or autoclass is None:
            return None
        try:
            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            act = PythonActivity.mActivity
            pkg = act.getApplicationContext().getPackageName()
            return autoclass(f"{pkg}.ServiceMedservice")
        except Exception:
            return None

    def start_bg_service(self):
        scr = self.root.ids.screen_manager.get_screen("meds")
        if _kivy_platform != "android":
            scr.ids.action_result.text = "Background service is Android-only."
            return
        svc = self._service_class()
        if not svc:
            scr.ids.action_result.text = "Service class not found (check buildozer.spec services=...)."
            return
        try:
            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            act = PythonActivity.mActivity
            svc.start(act, "icon", "MedSafe", "Reminders active", "")
            scr.ids.action_result.text = "Background reminders started."
        except Exception as e:
            scr.ids.action_result.text = f"Start failed: {e}"

    def stop_bg_service(self):
        scr = self.root.ids.screen_manager.get_screen("meds")
        if _kivy_platform != "android":
            scr.ids.action_result.text = "Background service is Android-only."
            return
        svc = self._service_class()
        if not svc:
            scr.ids.action_result.text = "Service class not found."
            return
        try:
            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            act = PythonActivity.mActivity
            svc.stop(act)
            scr.ids.action_result.text = "Background reminders stopped."
        except Exception as e:
            scr.ids.action_result.text = f"Stop failed: {e}"


if __name__ == "__main__":
    MedSafeApp().run()
