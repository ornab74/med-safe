
import os
import sys
import time
import json
import hashlib
import asyncio
import threading
import httpx
import aiosqlite
import math
import random
import re
import uuid
import logging

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Tuple, Callable, Dict
from contextlib import contextmanager
from threading import RLock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from jnius import autoclass, cast
except Exception:
    autoclass = None
    cast = None

try:
    import psutil
except Exception:
    psutil = None

try:
    import pennylane as qml
    from pennylane import numpy as pnp
except Exception:
    qml = None
    pnp = None

from kivy.lang import Builder
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.uix.widget import Widget
from kivy.metrics import dp
from kivy.graphics import Color, Line, RoundedRectangle, Rectangle
from kivy.properties import NumericProperty, StringProperty, ListProperty
from kivy.utils import platform as _kivy_platform

from kivymd.app import MDApp
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDFlatButton, MDRaisedButton
from kivymd.uix.list import TwoLineListItem, MDList
from kivymd.uix.textfield import MDTextField
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.progressbar import MDProgressBar
from kivymd.uix.toolbar import MDTopAppBar
from kivymd.uix.label import MDLabel
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem
from kivymd.uix.screen import MDScreen

if _kivy_platform != "android" and hasattr(Window, "size"):
    Window.size = (420, 760)

_CRYPTO_LOCK = RLock()
_MODEL_LOCK = RLock()
_LOG_LOCK = RLock()

_MODEL_USERS = 0
_ANDROID_KEY_ALIAS = "qroadscan_master_rsa_v1"

MAX_DB_BYTES = 2 * 1024 * 1024
MAX_HISTORY_ROWS = 500


def _is_writable_dir(p: Path) -> bool:
    try:
        p.mkdir(parents=True, exist_ok=True)
        t = p / f".writetest.{uuid.uuid4().hex}"
        t.write_text("ok", encoding="utf-8")
        t.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _android_context():
    if _kivy_platform != "android" or autoclass is None:
        return None
    try:
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        return PythonActivity.mActivity
    except Exception:
        return None


def _android_files_dir() -> Optional[Path]:
    ctx = _android_context()
    if not ctx:
        return None
    try:
        return Path(str(ctx.getFilesDir().getAbsolutePath()))
    except Exception:
        return None


def _android_external_files_dir() -> Optional[Path]:
    ctx = _android_context()
    if not ctx:
        return None
    try:
        ext = ctx.getExternalFilesDir(None)
        if ext is None:
            return None
        return Path(str(ext.getAbsolutePath()))
    except Exception:
        return None


def _app_base_dir() -> Path:
    if _kivy_platform == "android":
        ext = _android_external_files_dir()
        if ext:
            d = ext / "qroadscan_data"
            if _is_writable_dir(d):
                return d
        internal = _android_files_dir()
        if internal:
            d = internal / "qroadscan_data"
            d.mkdir(parents=True, exist_ok=True)
            return d
        p = os.environ.get("ANDROID_PRIVATE")
        if p:
            d = Path(p) / "qroadscan_data"
            d.mkdir(parents=True, exist_ok=True)
            return d
        d = Path.cwd() / "qroadscan_data"
        d.mkdir(parents=True, exist_ok=True)
        return d
    base = Path(__file__).resolve().parent
    d = base / "qroadscan_data"
    d.mkdir(parents=True, exist_ok=True)
    return d


BASE_DIR = _app_base_dir()

MODEL_REPO = "https://huggingface.co/tensorblock/llama3-small-GGUF/resolve/main/"
MODEL_FILE = "llama3-small-Q3_K_M.gguf"
EXPECTED_HASH = "8e4f4856fb84bafb895f1eb08e6c03e4be613ead2d942f91561aeac742a619aa"

MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / MODEL_FILE
ENCRYPTED_MODEL = MODEL_PATH.with_suffix(MODEL_PATH.suffix + ".aes")

DB_PATH = BASE_DIR / "chat_history.db.aes"
KEY_PATH = BASE_DIR / ".enc_key_wrapped"
LOG_PATH = BASE_DIR / "debug.log"
TMP_DIR = BASE_DIR / "tmp"

TMP_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)


class _RingLog:
    def __init__(self, max_lines=600):
        self.max_lines = int(max_lines)
        self._lines: List[str] = []
        self._lock = RLock()

    def add(self, line: str):
        line = (line or "").rstrip("\n")
        if not line:
            return
        with self._lock:
            self._lines.append(line)
            if len(self._lines) > self.max_lines:
                self._lines = self._lines[-self.max_lines :]

    def text(self) -> str:
        with self._lock:
            return "\n".join(self._lines)

    def clear(self):
        with self._lock:
            self._lines = []


_RING = _RingLog()


class _FileAndRingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self._fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    def emit(self, record):
        try:
            msg = self._fmt.format(record)
        except Exception:
            msg = str(record.getMessage())

        _RING.add(msg)

        try:
            with _LOG_LOCK:
                LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
                with LOG_PATH.open("a", encoding="utf-8") as f:
                    f.write(msg + "\n")
        except Exception:
            pass

        try:
            app = MDApp.get_running_app()
            if app and hasattr(app, "_debug_dirty"):
                app._debug_dirty = True
        except Exception:
            pass


logger = logging.getLogger("qroadscan")
logger.setLevel(logging.INFO)
if not any(isinstance(h, _FileAndRingHandler) for h in logger.handlers):
    logger.addHandler(_FileAndRingHandler())


def _atomic_write_bytes(path: Path, data: bytes):
    tmp = path.with_suffix(
        path.suffix
        + f".tmp.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}"
    )
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_bytes(data)
    tmp.replace(path)


def _tmp_path(prefix: str, suffix: str) -> Path:
    return TMP_DIR / f"{prefix}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}{suffix}"


def _cleanup_tmp_dir():
    try:
        TMP_DIR.mkdir(parents=True, exist_ok=True)
        patterns = [
            "hist_*.db",
            "db_rekey*.db",
            "model_rekey*.gguf",
            "*.dl.*",
            "*.enc.*",
            "*.dec.*",
        ]
        removed = 0
        for pat in patterns:
            for p in TMP_DIR.glob(pat):
                try:
                    p.unlink(missing_ok=True)
                    removed += 1
                except Exception:
                    pass
        if removed:
            logger.info("tmp cleanup removed=%d", removed)
    except Exception:
        pass


def _derive_subkey(master_key: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)


def _db_key(master_key: bytes) -> bytes:
    return _derive_subkey(master_key, b"qroadscan/db/v1")


def _model_key(master_key: bytes) -> bytes:
    return _derive_subkey(master_key, b"qroadscan/model/v1")


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data, None)


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    if not data or len(data) < 12:
        raise InvalidTag("ciphertext too short")
    aes = AESGCM(key)
    nonce, ct = data[:12], data[12:]
    return aes.decrypt(nonce, ct, None)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _android_ready() -> bool:
    return _kivy_platform == "android" and autoclass is not None and cast is not None


def _android_keystore_get():
    KeyStore = autoclass("java.security.KeyStore")
    ks = KeyStore.getInstance("AndroidKeyStore")
    ks.load(None)
    return ks


def _android_keystore_ensure_rsa(alias: str):
    ks = _android_keystore_get()
    if ks.containsAlias(alias):
        return
    KeyPairGenerator = autoclass("java.security.KeyPairGenerator")
    KeyProperties = autoclass("android.security.keystore.KeyProperties")
    KeyGenParameterSpecBuilder = autoclass(
        "android.security.keystore.KeyGenParameterSpec$Builder"
    )
    purposes = int(KeyProperties.PURPOSE_ENCRYPT) | int(KeyProperties.PURPOSE_DECRYPT)
    builder = KeyGenParameterSpecBuilder(alias, purposes)
    builder.setDigests([KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512])
    builder.setEncryptionPaddings([KeyProperties.ENCRYPTION_PADDING_RSA_OAEP])
    spec = builder.build()
    kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
    kpg.initialize(spec)
    kpg.generateKeyPair()


def _android_keystore_wrap_key(aes_key: bytes) -> bytes:
    _android_keystore_ensure_rsa(_ANDROID_KEY_ALIAS)
    ks = _android_keystore_get()
    cert = ks.getCertificate(_ANDROID_KEY_ALIAS)
    pub = cert.getPublicKey()
    CipherJ = autoclass("javax.crypto.Cipher")
    cipher = CipherJ.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    cipher.init(CipherJ.ENCRYPT_MODE, pub)
    return bytes(cipher.doFinal(aes_key))


def _android_keystore_unwrap_key(wrapped: bytes) -> bytes:
    _android_keystore_ensure_rsa(_ANDROID_KEY_ALIAS)
    ks = _android_keystore_get()
    entry = ks.getEntry(_ANDROID_KEY_ALIAS, None)
    priv = entry.getPrivateKey()
    CipherJ = autoclass("javax.crypto.Cipher")
    cipher = CipherJ.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    cipher.init(CipherJ.DECRYPT_MODE, priv)
    return bytes(cipher.doFinal(wrapped))


def _store_wrapped_key(raw_key: bytes):
    if _android_ready():
        wrapped = _android_keystore_wrap_key(raw_key)
        _atomic_write_bytes(KEY_PATH, wrapped)
        logger.info("key stored: android keystore wrapped")
    else:
        _atomic_write_bytes(KEY_PATH, raw_key)
        logger.info("key stored: file raw (non-android)")


def _load_wrapped_key() -> Optional[bytes]:
    if not KEY_PATH.exists():
        return None
    d = KEY_PATH.read_bytes()
    if _android_ready():
        try:
            k = _android_keystore_unwrap_key(d)
            if len(k) == 32:
                logger.info("key loaded: android keystore unwrapped")
                return k
            return None
        except Exception:
            logger.exception("key unwrap failed")
            return None
    k = d[:32] if len(d) >= 32 else None
    if k:
        logger.info("key loaded: file raw (non-android)")
    return k


def get_or_create_key() -> bytes:
    with _CRYPTO_LOCK:
        k = _load_wrapped_key()
        if k and len(k) == 32:
            return k
        key = AESGCM.generate_key(256)
        try:
            _store_wrapped_key(key)
        except Exception:
            _atomic_write_bytes(KEY_PATH, key)
            logger.exception("key store failed, fell back to raw file write")
        return key


def derive_key_from_passphrase(pw: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf_der = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    derived = kdf_der.derive(pw.encode("utf-8"))
    return salt, derived


def download_model_httpx_with_cb(
    url: str,
    dest: Path,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    timeout=None,
) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    with httpx.stream("GET", url, follow_redirects=True, timeout=timeout) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        tmp = dest.with_suffix(dest.suffix + f".dl.{uuid.uuid4().hex}")
        try:
            with tmp.open("wb") as f:
                for chunk in r.iter_bytes(chunk_size=1024 * 256):
                    if not chunk:
                        break
                    f.write(chunk)
                    h.update(chunk)
                    done += len(chunk)
                    if progress_cb:
                        progress_cb(done, total)
            tmp.replace(dest)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
    return h.hexdigest()


def encrypt_file(src: Path, dest: Path, key: bytes, chunk_size: int = 1024 * 1024):
    with _CRYPTO_LOCK:
        nonce = os.urandom(12)
        enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        tmp = dest.with_suffix(dest.suffix + f".enc.{uuid.uuid4().hex}")
        with src.open("rb") as fin, tmp.open("wb") as fout:
            fout.write(nonce)
            while True:
                buf = fin.read(chunk_size)
                if not buf:
                    break
                fout.write(enc.update(buf))
            enc.finalize()
            fout.write(enc.tag)
        tmp.replace(dest)


def decrypt_file(src: Path, dest: Path, key: bytes, chunk_size: int = 1024 * 1024):
    with _CRYPTO_LOCK:
        with src.open("rb") as fin:
            nonce = fin.read(12)
            fin.seek(0, os.SEEK_END)
            total = fin.tell()
            if total < 12 + 16:
                raise InvalidTag("ciphertext too short")
            tag_pos = total - 16
            fin.seek(tag_pos)
            tag = fin.read(16)
            fin.seek(12)
            dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            tmp = dest.with_suffix(dest.suffix + f".dec.{uuid.uuid4().hex}")
            with tmp.open("wb") as fout:
                remaining = tag_pos - 12
                while remaining > 0:
                    n = min(chunk_size, remaining)
                    buf = fin.read(n)
                    if not buf:
                        break
                    remaining -= len(buf)
                    fout.write(dec.update(buf))
                dec.finalize()
            tmp.replace(dest)


def _mark_corrupt(path: Path):
    try:
        ts = time.strftime("%Y%m%d_%H%M%S")
        dst = path.with_suffix(path.suffix + f".corrupt.{ts}.{uuid.uuid4().hex}")
        path.replace(dst)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass


def _safe_decrypt_db_to(tmp_plain: Path, master_key: bytes) -> bool:
    if not DB_PATH.exists():
        return False
    try:
        try:
            if DB_PATH.stat().st_size > MAX_DB_BYTES:
                logger.warning("db too large (%d bytes), archiving", DB_PATH.stat().st_size)
                _mark_corrupt(DB_PATH)
                return False
        except Exception:
            pass
        with _CRYPTO_LOCK:
            pt = aes_decrypt(DB_PATH.read_bytes(), _db_key(master_key))
            _atomic_write_bytes(tmp_plain, pt)
        return True
    except InvalidTag:
        logger.warning("db decrypt invalid tag, marked corrupt")
        _mark_corrupt(DB_PATH)
        return False
    except Exception:
        logger.exception("db decrypt failed")
        return False


def _encrypt_db_from_plain(tmp_plain: Path, master_key: bytes):
    with _CRYPTO_LOCK:
        enc = aes_encrypt(tmp_plain.read_bytes(), _db_key(master_key))
        _atomic_write_bytes(DB_PATH, enc)


async def init_db(master_key: bytes):
    if DB_PATH.exists():
        return
    tmp_plain = _tmp_path("hist_init", ".db")
    try:
        async with aiosqlite.connect(str(tmp_plain)) as db:
            await db.execute(
                "CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, prompt TEXT, response TEXT)"
            )
            await db.commit()
        _encrypt_db_from_plain(tmp_plain, master_key)
        logger.info("db init ok")
    finally:
        try:
            tmp_plain.unlink(missing_ok=True)
        except Exception:
            pass


async def log_interaction(prompt: str, response: str, master_key: bytes):
    if not DB_PATH.exists():
        await init_db(master_key)

    tmp_plain = _tmp_path("hist_work", ".db")
    try:
        if not _safe_decrypt_db_to(tmp_plain, master_key):
            await init_db(master_key)
            if not _safe_decrypt_db_to(tmp_plain, master_key):
                return

        async with aiosqlite.connect(str(tmp_plain)) as db:
            await db.execute(
                "INSERT INTO history (timestamp, prompt, response) VALUES (?, ?, ?)",
                (time.strftime("%Y-%m-%d %H:%M:%S"), prompt, response),
            )
            await db.execute(
                "DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT ?)",
                (MAX_HISTORY_ROWS,),
            )
            await db.commit()

        _encrypt_db_from_plain(tmp_plain, master_key)
    finally:
        try:
            tmp_plain.unlink(missing_ok=True)
        except Exception:
            pass


async def fetch_history(master_key: bytes, limit: int = 20, offset: int = 0, search: Optional[str] = None):
    if not DB_PATH.exists():
        await init_db(master_key)

    tmp_plain = _tmp_path("hist_read", ".db")
    rows = []
    try:
        if not _safe_decrypt_db_to(tmp_plain, master_key):
            await init_db(master_key)
            if not _safe_decrypt_db_to(tmp_plain, master_key):
                return []

        async with aiosqlite.connect(str(tmp_plain)) as db:
            if search:
                q = f"%{search}%"
                async with db.execute(
                    "SELECT id,timestamp,prompt,response FROM history WHERE prompt LIKE ? OR response LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                    (q, q, limit, offset),
                ) as cur:
                    async for r in cur:
                        rows.append(r)
            else:
                async with db.execute(
                    "SELECT id,timestamp,prompt,response FROM history ORDER BY id DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ) as cur:
                    async for r in cur:
                        rows.append(r)
    finally:
        try:
            tmp_plain.unlink(missing_ok=True)
        except Exception:
            pass

    return rows


def _get_llama_class():
    from llama_cpp import Llama
    return Llama


def load_llama_model_blocking(model_path: Path):
    Llama = _get_llama_class()
    return Llama(
        model_path=str(model_path),
        n_ctx=2048,
        n_threads=max(2, (os.cpu_count() or 4) // 2),
    )


def _read_proc_stat():
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
        if not line.startswith("cpu "):
            return None
        parts = line.split()
        vals = [int(x) for x in parts[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals)
        return total, idle
    except Exception:
        return None


def _cpu_percent_from_proc(sample_interval=0.12):
    t1 = _read_proc_stat()
    if not t1:
        return None
    time.sleep(sample_interval)
    t2 = _read_proc_stat()
    if not t2:
        return None
    total1, idle1 = t1
    total2, idle2 = t2
    total_delta = total2 - total1
    idle_delta = idle2 - idle1
    if total_delta <= 0:
        return None
    usage = (total_delta - idle_delta) / float(total_delta)
    return max(0.0, min(1.0, usage))


def _mem_from_proc():
    try:
        info = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                k = parts[0].strip()
                v = parts[1].strip().split()[0]
                info[k] = int(v)
        total = info.get("MemTotal")
        available = info.get("MemAvailable", None)
        if total is None:
            return None
        if available is None:
            available = info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0)
        used_fraction = max(0.0, min(1.0, (total - available) / float(total)))
        return used_fraction
    except Exception:
        return None


def _load1_from_proc(cpu_count_fallback=1):
    try:
        with open("/proc/loadavg", "r") as f:
            first = f.readline().split()[0]
        load1 = float(first)
        try:
            cpu_cnt = os.cpu_count() or cpu_count_fallback
        except Exception:
            cpu_cnt = cpu_count_fallback
        val = load1 / max(1.0, float(cpu_cnt))
        return max(0.0, min(1.0, val))
    except Exception:
        return None


def _proc_count_from_proc():
    try:
        pids = [name for name in os.listdir("/proc") if name.isdigit()]
        return max(0.0, min(1.0, len(pids) / 1000.0))
    except Exception:
        return None


def _read_temperature():
    temps = []
    try:
        base = "/sys/class/thermal"
        if os.path.isdir(base):
            for entry in os.listdir(base):
                if not entry.startswith("thermal_zone"):
                    continue
                path = os.path.join(base, entry, "temp")
                try:
                    with open(path, "r") as f:
                        raw = f.read().strip()
                    if not raw:
                        continue
                    val = int(raw)
                    c = val / 1000.0 if val > 1000 else float(val)
                    temps.append(c)
                except Exception:
                    continue
        if not temps:
            return None
        avg_c = sum(temps) / len(temps)
        norm = (avg_c - 20.0) / (90.0 - 20.0)
        return max(0.0, min(1.0, norm))
    except Exception:
        return None


def collect_system_metrics() -> Dict[str, float]:
    cpu = mem = load1 = temp = proc = None

    if psutil is not None:
        try:
            cpu = psutil.cpu_percent(interval=0.1) / 100.0
            mem = psutil.virtual_memory().percent / 100.0
            try:
                load_raw = os.getloadavg()[0]
                cpu_cnt = psutil.cpu_count(logical=True) or 1
                load1 = max(0.0, min(1.0, load_raw / max(1.0, float(cpu_cnt))))
            except Exception:
                load1 = None
            try:
                temps_map = psutil.sensors_temperatures()
                if temps_map:
                    first = next(iter(temps_map.values()))[0].current
                    temp = max(0.0, min(1.0, (first - 20.0) / 70.0))
                else:
                    temp = None
            except Exception:
                temp = None
            try:
                proc = min(len(psutil.pids()) / 1000.0, 1.0)
            except Exception:
                proc = None
        except Exception:
            cpu = mem = load1 = temp = proc = None

    if cpu is None:
        cpu = _cpu_percent_from_proc()
    if mem is None:
        mem = _mem_from_proc()
    if load1 is None:
        load1 = _load1_from_proc()
    if proc is None:
        proc = _proc_count_from_proc()
    if temp is None:
        temp = _read_temperature()

    cpu = float(max(0.0, min(1.0, float(cpu or 0.0))))
    mem = float(max(0.0, min(1.0, float(mem or 0.0))))
    load1 = float(max(0.0, min(1.0, float(load1 or 0.0))))
    proc = float(max(0.0, min(1.0, float(proc or 0.0))))
    temp = float(max(0.0, min(1.0, float(temp or 0.0))))

    return {"cpu": cpu, "mem": mem, "load1": load1, "temp": temp, "proc": proc}


def metrics_to_rgb(metrics: dict) -> Tuple[float, float, float]:
    cpu = metrics.get("cpu", 0.1)
    mem = metrics.get("mem", 0.1)
    temp = metrics.get("temp", 0.1)
    load1 = metrics.get("load1", 0.0)
    proc = metrics.get("proc", 0.0)

    r = cpu * (1.0 + load1)
    g = mem * (1.0 + proc)
    b = temp * (0.5 + cpu * 0.5)

    maxi = max(r, g, b, 1.0)
    r, g, b = r / maxi, g / maxi, b / maxi
    return (
        float(max(0.0, min(1.0, r))),
        float(max(0.0, min(1.0, g))),
        float(max(0.0, min(1.0, b))),
    )


def pennylane_entropic_score(rgb: Tuple[float, float, float], shots: int = 256) -> float:
    if qml is None or pnp is None:
        r, g, b = rgb
        seed = int((int(r * 255) << 16) | (int(g * 255) << 8) | int(b * 255))
        random.seed(seed)
        base = (0.3 * r + 0.4 * g + 0.3 * b)
        noise = (random.random() - 0.5) * 0.08
        return max(0.0, min(1.0, base + noise))

    dev = qml.device("default.qubit", wires=2, shots=shots)

    @qml.qnode(dev)
    def circuit(a, b, c):
        qml.RX(a * math.pi, wires=0)
        qml.RY(b * math.pi, wires=1)
        qml.CNOT(wires=[0, 1])
        qml.RZ(c * math.pi, wires=1)
        qml.RX((a + b) * math.pi / 2, wires=0)
        qml.RY((b + c) * math.pi / 2, wires=1)
        return qml.expval(qml.PauliZ(0)), qml.expval(qml.PauliZ(1))

    a, b, c = float(rgb[0]), float(rgb[1]), float(rgb[2])
    try:
        ev0, ev1 = circuit(a, b, c)
        combined = ((ev0 + 1.0) / 2.0 * 0.6 + (ev1 + 1.0) / 2.0 * 0.4)
        score = 1.0 / (1.0 + math.exp(-6.0 * (combined - 0.5)))
        return float(max(0.0, min(1.0, score)))
    except Exception:
        return float(0.5 * (a + b + c) / 3.0)


def entropic_summary_text(score: float) -> str:
    if score >= 0.75:
        level = "high"
    elif score >= 0.45:
        level = "medium"
    else:
        level = "low"
    return f"entropic_score={score:.3f} (level={level})"


def _simple_tokenize(text: str) -> List[str]:
    return [t for t in re.findall(r"[A-Za-z0-9_\-]+", (text or "").lower())]


def punkd_analyze(prompt_text: str, top_n: int = 12) -> Dict[str, float]:
    toks = _simple_tokenize(prompt_text)
    freq: Dict[str, float] = {}
    for t in toks:
        freq[t] = freq.get(t, 0) + 1

    hazard_boost = {
        "ice": 2.0,
        "wet": 1.8,
        "snow": 2.0,
        "flood": 2.0,
        "construction": 1.8,
        "pedestrian": 1.8,
        "debris": 1.8,
        "animal": 1.5,
        "stall": 1.4,
        "fog": 1.6,
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
    profile_map = {"conservative": 0.6, "balanced": 1.0, "aggressive": 1.4}
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
    max_total_tokens: int = 256,
    chunk_tokens: int = 64,
    base_temperature: float = 0.2,
    punkd_profile: str = "balanced",
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
            try:
                text = str(out)
            except Exception:
                text = ""

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

        if assembled.strip().endswith(("Low", "Medium", "High")):
            break
        if len(text.split()) < max(4, chunk_tokens // 8):
            break

        cur_prompt = prompt + "\n\nAssistant so far:\n" + assembled + "\n\nContinue:"

    return assembled.strip()


def build_road_scanner_prompt(data: dict, include_system_entropy: bool = True) -> str:
    entropy_text = "entropic_score=unknown"
    if include_system_entropy:
        metrics = collect_system_metrics()
        rgb = metrics_to_rgb(metrics)
        score = pennylane_entropic_score(rgb)
        entropy_text = entropic_summary_text(score)
        metrics_line = "sys_metrics: cpu={cpu:.2f},mem={mem:.2f},load={load1:.2f},temp={temp:.2f},proc={proc:.2f}".format(
            cpu=metrics.get("cpu", 0.0),
            mem=metrics.get("mem", 0.0),
            load1=metrics.get("load1", 0.0),
            temp=metrics.get("temp", 0.0),
            proc=metrics.get("proc", 0.0),
        )
    else:
        metrics_line = "sys_metrics: disabled"

    return (
        "You are a Hypertime Nanobot specialized Road Risk Classification AI trained to evaluate real-world driving scenes.\n"
        "Analyze and Triple Check for validating accuracy the environmental and sensor data and determine the overall road risk level.\n"
        "Your reply must be only one word: Low, Medium, or High.\n\n"
        "[tuning]\n"
        "Scene details:\n"
        f"Location: {data.get('location','unspecified location')}\n"
        f"Road type: {data.get('road_type','unknown')}\n"
        f"Weather: {data.get('weather','unknown')}\n"
        f"Traffic: {data.get('traffic','unknown')}\n"
        f"Obstacles: {data.get('obstacles','none')}\n"
        f"Sensor notes: {data.get('sensor_notes','none')}\n"
        f"{metrics_line}\n"
        f"Quantum State: {entropy_text}\n"
        "[/tuning]\n\n"
        "Follow these strict rules when forming your decision:\n"
        "- Think through all scene factors internally but do not show reasoning.\n"
        "- Evaluate surface, visibility, weather, traffic, and obstacles holistically.\n"
        "- Optionally use the system entropic signal to bias your internal confidence slightly.\n"
        "- Choose only one risk level that best fits the entire situation.\n"
        "- Output exactly one word, with no punctuation or labels.\n"
        "- The valid outputs are only: Low, Medium, High.\n\n"
        "[action]\n"
        "1) Normalize sensor inputs to comparable scales.\n"
        "3) Map environmental risk cues -> discrete label using conservative thresholds.\n"
        "4) If sensor integrity anomalies are detected, bias toward higher risk.\n"
        "5) PUNKD: detect key tokens and locally adjust attention/temperature slightly to focus decisions.\n"
        "6) Do not output internal reasoning or diagnostics; only return the single-word label.\n"
        "[/action]\n\n"
        "[replytemplate]\n"
        "Low | Medium | High\n"
        "[/replytemplate]"
    )


async def mobile_ensure_init() -> bytes:
    master = get_or_create_key()
    try:
        await init_db(master)
    except Exception:
        logger.exception("init db failed")
    _cleanup_tmp_dir()
    return master


@contextmanager
def acquire_plain_model(master_key: bytes):
    global _MODEL_USERS
    mkey = _model_key(master_key)
    with _MODEL_LOCK:
        if ENCRYPTED_MODEL.exists() and not MODEL_PATH.exists():
            decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, mkey)
            logger.info("model decrypted to plaintext")
        if not MODEL_PATH.exists() and not ENCRYPTED_MODEL.exists():
            raise FileNotFoundError("Model not found")
        _MODEL_USERS += 1
    try:
        yield MODEL_PATH
    finally:
        with _MODEL_LOCK:
            _MODEL_USERS = max(0, _MODEL_USERS - 1)
            if _MODEL_USERS == 0 and ENCRYPTED_MODEL.exists() and MODEL_PATH.exists():
                try:
                    encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, mkey)
                    MODEL_PATH.unlink(missing_ok=True)
                    logger.info("model re-encrypted and plaintext deleted")
                except Exception:
                    logger.exception("model re-encrypt failed")


async def mobile_run_road_scan(data: dict) -> Tuple[str, str]:
    master = await mobile_ensure_init()
    prompt = build_road_scanner_prompt(data, include_system_entropy=True)

    try:
        with acquire_plain_model(master) as model_path:
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor(max_workers=1) as ex:
                try:
                    llm = await loop.run_in_executor(ex, load_llama_model_blocking, model_path)
                except Exception as e:
                    logger.exception("model load failed")
                    return "[Error]", f"[Error loading model: {e}]"

                def run_chunked():
                    return chunked_generate(
                        llm=llm,
                        prompt=prompt,
                        max_total_tokens=256,
                        chunk_tokens=64,
                        base_temperature=0.18,
                        punkd_profile="balanced",
                        streaming_callback=None,
                    )

                result = await loop.run_in_executor(ex, run_chunked)
                text = (result or "").strip().replace(
                    "You are a helpful AI assistant named SmolLM, trained by Hugging Face", ""
                )

                candidate = text.split()
                label = candidate[0].capitalize() if candidate else ""

                if label not in ("Low", "Medium", "High"):
                    lowered = text.lower()
                    if "low" in lowered:
                        label = "Low"
                    elif "medium" in lowered:
                        label = "Medium"
                    elif "high" in lowered:
                        label = "High"
                    else:
                        label = "Medium"

                try:
                    await log_interaction("ROAD_SCANNER_PROMPT:\n" + prompt, "ROAD_SCANNER_RESULT:\n" + label, master)
                except Exception:
                    logger.exception("log interaction failed")

                try:
                    del llm
                except Exception:
                    pass

                return label, text
    except FileNotFoundError:
        return "[Model not found]", "[Model not found. Place or download the GGUF model on device.]"


class BackgroundGradient(Widget):
    top_color = ListProperty([0.07, 0.09, 0.14, 1])
    bottom_color = ListProperty([0.02, 0.03, 0.05, 1])
    steps = NumericProperty(44)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw,
                  top_color=self._redraw, bottom_color=self._redraw,
                  steps=self._redraw)

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
    radius = NumericProperty(dp(26))
    fill = ListProperty([1, 1, 1, 0.055])
    border = ListProperty([1, 1, 1, 0.13])
    highlight = ListProperty([1, 1, 1, 0.08])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw,
                  radius=self._redraw, fill=self._redraw,
                  border=self._redraw, highlight=self._redraw)

    def _redraw(self, *args):
        self.canvas.clear()
        x, y = self.pos
        w, h = self.size
        r = float(self.radius)
        with self.canvas:
            Color(0, 0, 0, 0.22)
            RoundedRectangle(pos=(x, y - dp(2)), size=(w, h + dp(3)), radius=[r])
            Color(*self.fill)
            RoundedRectangle(pos=(x, y), size=(w, h), radius=[r])
            Color(*self.highlight)
            RoundedRectangle(pos=(x + dp(1), y + h * 0.55), size=(w - dp(2), h * 0.45), radius=[r])
            Color(*self.border)
            Line(rounded_rectangle=[x, y, w, h, r], width=dp(1.1))


class RiskWheelNeo(Widget):
    value = NumericProperty(0.5)
    level = StringProperty("MEDIUM")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, value=self._redraw, level=self._redraw)

    def set_level(self, level: str):
        lvl = (level or "").strip().upper()
        if lvl.startswith("LOW"):
            self.level = "LOW"
            self.value = 0.0
        elif lvl.startswith("HIGH"):
            self.level = "HIGH"
            self.value = 1.0
        else:
            self.level = "MEDIUM"
            self.value = 0.5

    def _level_color(self):
        if self.level == "LOW":
            return (0.10, 0.90, 0.42)
        if self.level == "HIGH":
            return (0.98, 0.22, 0.30)
        return (0.98, 0.78, 0.20)

    def _redraw(self, *args):
        self.canvas.clear()
        cx, cy = self.center
        r = min(self.width, self.height) * 0.41
        thickness = max(dp(12), r * 0.16)

        ang = -135.0 + 270.0 * float(self.value)
        ang_rad = math.radians(ang)
        active_rgb = self._level_color()

        segs = [
            ("LOW", (0.10, 0.85, 0.40), -135.0, -45.0),
            ("MED", (0.98, 0.78, 0.20), -45.0, 45.0),
            ("HIGH", (0.98, 0.22, 0.30), 45.0, 135.0),
        ]
        gap = 6.0

        with self.canvas:
            Color(1, 1, 1, 0.05)
            Line(circle=(cx, cy, r + dp(10), -140, 140), width=dp(1.2))
            Color(0.10, 0.12, 0.18, 0.65)
            Line(circle=(cx, cy, r, -140, 140), width=thickness, cap="round")

            for name, rgb, a0, a1 in segs:
                a0g = a0 + gap / 2.0
                a1g = a1 - gap / 2.0
                Color(rgb[0], rgb[1], rgb[2], 0.78)
                Line(circle=(cx, cy, r, a0g, a1g), width=thickness, cap="round")

            nx = cx + math.cos(ang_rad) * (r * 0.92)
            ny = cy + math.sin(ang_rad) * (r * 0.92)
            Color(active_rgb[0], active_rgb[1], active_rgb[2], 0.22)
            Line(points=[cx, cy, nx, ny], width=max(dp(3.2), thickness * 0.16), cap="round")
            Color(0.97, 0.97, 0.99, 0.98)
            Line(points=[cx, cy, nx, ny], width=max(dp(2), thickness * 0.10), cap="round")

            Color(1, 1, 1, 0.08)
            RoundedRectangle(pos=(cx - dp(18), cy - dp(18)), size=(dp(36), dp(36)), radius=[dp(18)])
            Color(1, 1, 1, 0.18)
            Line(rounded_rectangle=[cx - dp(18), cy - dp(18), dp(36), dp(36), dp(18)], width=dp(1.0))
            Color(0.06, 0.07, 0.10, 0.9)
            RoundedRectangle(pos=(cx - dp(12), cy - dp(12)), size=(dp(24), dp(24)), radius=[dp(12)])


KV = r"""
<BackgroundGradient>:
    size_hint: 1, 1

<GlassCard>:
    size_hint: 1, None

<RiskWheelNeo>:
    size_hint: None, None

MDScreen:
    MDBoxLayout:
        orientation: "vertical"

        MDTopAppBar:
            title: "Road Safe"
            elevation: 10

        MDLabel:
            id: status_label
            text: ""
            size_hint_y: None
            height: "24dp"
            halign: "center"

        ScreenManager:
            id: screen_manager
            size_hint_y: 1

            MDScreen:
                name: "road"
                BackgroundGradient:
                    top_color: 0.07, 0.09, 0.14, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                MDBoxLayout:
                    orientation: "vertical"
                    padding: "10dp"
                    spacing: "10dp"

                    ScrollView:
                        do_scroll_x: False

                        FloatLayout:
                            size_hint_x: 1
                            size_hint_y: None
                            height: max(content.minimum_height, self.parent.height)

                            GlassCard:
                                pos: self.parent.pos
                                size: self.parent.size
                                radius: dp(26)
                                fill: 1, 1, 1, 0.055
                                border: 1, 1, 1, 0.13
                                highlight: 1, 1, 1, 0.08

                            MDBoxLayout:
                                id: content
                                orientation: "vertical"
                                size_hint_x: 1
                                width: self.parent.width
                                size_hint_y: None
                                height: self.minimum_height
                                x: self.parent.x
                                y: self.parent.y
                                padding: "14dp"
                                spacing: "10dp"

                                MDLabel:
                                    text: "Road Risk Scanner"
                                    bold: True
                                    font_style: "H6"
                                    halign: "center"
                                    size_hint_y: None
                                    height: "32dp"

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "250dp"
                                    padding: "6dp"
                                    RiskWheelNeo:
                                        id: risk_wheel
                                        size: "240dp", "240dp"
                                        pos_hint: {"center_x": 0.5, "center_y": 0.55}

                                MDLabel:
                                    id: risk_text
                                    text: "RISK: —"
                                    halign: "center"
                                    size_hint_y: None
                                    height: "22dp"

                                MDTextField:
                                    id: loc_field
                                    hint_text: "Location (e.g., I-95 NB mile 12)"
                                    mode: "fill"

                                MDTextField:
                                    id: road_type_field
                                    hint_text: "Road type (highway/urban/residential)"
                                    mode: "fill"

                                MDTextField:
                                    id: weather_field
                                    hint_text: "Weather/visibility"
                                    mode: "fill"

                                MDTextField:
                                    id: traffic_field
                                    hint_text: "Traffic density (low/med/high)"
                                    mode: "fill"

                                MDTextField:
                                    id: obstacles_field
                                    hint_text: "Reported obstacles"
                                    mode: "fill"

                                MDTextField:
                                    id: sensor_notes_field
                                    hint_text: "Sensor notes"
                                    mode: "fill"

                                MDRaisedButton:
                                    text: "Scan Risk"
                                    size_hint_x: 1
                                    on_release: app.on_scan()

                                MDLabel:
                                    id: scan_result
                                    text: ""
                                    halign: "center"
                                    size_hint_y: None
                                    height: "24dp"

            MDScreen:
                name: "model"
                BackgroundGradient:
                    top_color: 0.06, 0.08, 0.13, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                MDBoxLayout:
                    orientation: "vertical"
                    padding: "10dp"
                    spacing: "10dp"

                    FloatLayout:
                        GlassCard:
                            pos: self.parent.pos
                            size: self.parent.size
                            height: self.parent.height
                            radius: dp(26)
                            fill: 1, 1, 1, 0.05
                            border: 1, 1, 1, 0.12
                            highlight: 1, 1, 1, 0.07

                        MDBoxLayout:
                            orientation: "vertical"
                            padding: "14dp"
                            spacing: "10dp"
                            pos: self.parent.pos
                            size: self.parent.size

                            MDLabel:
                                text: "Model Manager"
                                bold: True
                                font_style: "H6"
                                size_hint_y: None
                                height: "32dp"

                            MDLabel:
                                id: model_status
                                text: "—"
                                theme_text_color: "Secondary"

                            MDProgressBar:
                                id: model_progress
                                value: 0
                                max: 100

                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "44dp"

                                MDRaisedButton:
                                    text: "Download"
                                    on_release: app.gui_model_download()

                                MDRaisedButton:
                                    text: "Verify SHA"
                                    on_release: app.gui_model_verify()

                                MDRaisedButton:
                                    text: "Encrypt"
                                    on_release: app.gui_model_encrypt()

                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "44dp"

                                MDRaisedButton:
                                    text: "Decrypt"
                                    on_release: app.gui_model_decrypt()

                                MDRaisedButton:
                                    text: "Delete plain"
                                    on_release: app.gui_model_delete_plain()

                                MDRaisedButton:
                                    text: "Refresh"
                                    on_release: app.gui_model_refresh()

            MDScreen:
                name: "history"
                BackgroundGradient:
                    top_color: 0.06, 0.08, 0.13, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                MDBoxLayout:
                    orientation: "vertical"
                    padding: "10dp"
                    spacing: "10dp"

                    FloatLayout:
                        GlassCard:
                            pos: self.parent.pos
                            size: self.parent.size
                            height: self.parent.height
                            radius: dp(26)
                            fill: 1, 1, 1, 0.05
                            border: 1, 1, 1, 0.12
                            highlight: 1, 1, 1, 0.07

                        MDBoxLayout:
                            orientation: "vertical"
                            padding: "14dp"
                            spacing: "10dp"
                            pos: self.parent.pos
                            size: self.parent.size

                            MDLabel:
                                text: "History"
                                bold: True
                                font_style: "H6"
                                size_hint_y: None
                                height: "32dp"

                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "48dp"

                                MDTextField:
                                    id: history_search
                                    hint_text: "Search prompt/response"
                                    mode: "fill"

                                MDRaisedButton:
                                    text: "Search"
                                    on_release: app.gui_history_search()

                                MDRaisedButton:
                                    text: "Clear"
                                    on_release: app.gui_history_clear()

                            MDLabel:
                                id: history_meta
                                text: "—"
                                theme_text_color: "Secondary"
                                size_hint_y: None
                                height: "22dp"

                            ScrollView:
                                MDList:
                                    id: history_list

                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "44dp"

                                MDRaisedButton:
                                    text: "Prev"
                                    on_release: app.gui_history_prev()

                                MDRaisedButton:
                                    text: "Next"
                                    on_release: app.gui_history_next()

                                MDRaisedButton:
                                    text: "Refresh"
                                    on_release: app.gui_history_refresh()

            MDScreen:
                name: "security"
                BackgroundGradient:
                    top_color: 0.06, 0.08, 0.13, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                MDBoxLayout:
                    orientation: "vertical"
                    padding: "10dp"
                    spacing: "10dp"

                    FloatLayout:
                        GlassCard:
                            pos: self.parent.pos
                            size: self.parent.size
                            height: self.parent.height
                            radius: dp(26)
                            fill: 1, 1, 1, 0.05
                            border: 1, 1, 1, 0.12
                            highlight: 1, 1, 1, 0.07

                        MDBoxLayout:
                            orientation: "vertical"
                            padding: "14dp"
                            spacing: "10dp"
                            pos: self.parent.pos
                            size: self.parent.size

                            MDLabel:
                                text: "Security"
                                bold: True
                                font_style: "H6"
                                size_hint_y: None
                                height: "32dp"

                            MDLabel:
                                text: "Rotate the encryption key and re-encrypt model + DB."
                                theme_text_color: "Secondary"

                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "44dp"

                                MDRaisedButton:
                                    text: "New random key"
                                    on_release: app.gui_rekey_random()

                                MDRaisedButton:
                                    text: "Passphrase key"
                                    on_release: app.gui_rekey_passphrase_dialog()

                            MDProgressBar:
                                id: rekey_progress
                                value: 0
                                max: 100

                            MDLabel:
                                id: rekey_status
                                text: "—"
                                theme_text_color: "Secondary"

            MDScreen:
                name: "debug"
                BackgroundGradient:
                    top_color: 0.06, 0.08, 0.13, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                MDBoxLayout:
                    orientation: "vertical"
                    padding: "10dp"
                    spacing: "10dp"

                    FloatLayout:
                        GlassCard:
                            pos: self.parent.pos
                            size: self.parent.size
                            height: self.parent.height
                            radius: dp(26)
                            fill: 1, 1, 1, 0.05
                            border: 1, 1, 1, 0.12
                            highlight: 1, 1, 1, 0.07

                        MDBoxLayout:
                            orientation: "vertical"
                            padding: "14dp"
                            spacing: "10dp"
                            pos: self.parent.pos
                            size: self.parent.size

                            MDLabel:
                                text: "Debug Log"
                                bold: True
                                font_style: "H6"
                                size_hint_y: None
                                height: "32dp"

                            MDLabel:
                                id: debug_meta
                                text: "—"
                                theme_text_color: "Secondary"
                                size_hint_y: None
                                height: "22dp"

                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "44dp"

                                MDRaisedButton:
                                    text: "Refresh"
                                    on_release: app.gui_debug_refresh()

                                MDRaisedButton:
                                    text: "Clear"
                                    on_release: app.gui_debug_clear()

                                MDRaisedButton:
                                    text: "Emit test"
                                    on_release: app.gui_debug_emit_test()

                            ScrollView:
                                MDLabel:
                                    id: debug_text
                                    text: ""
                                    markup: False
                                    size_hint_y: None
                                    height: self.texture_size[1]

        MDBottomNavigation:
            id: bottom_nav
            size_hint_y: None
            height: "72dp"
            panel_color: 0.08,0.09,0.12,1

            MDBottomNavigationItem:
                name: "nav_road"
                text: "Road"
                icon: "road-variant"
                on_tab_press: app.switch_screen("road")

            MDBottomNavigationItem:
                name: "nav_model"
                text: "Model"
                icon: "cube-outline"
                on_tab_press: app.switch_screen("model")

            MDBottomNavigationItem:
                name: "nav_history"
                text: "History"
                icon: "history"
                on_tab_press: app.switch_screen("history")

            MDBottomNavigationItem:
                name: "nav_security"
                text: "Security"
                icon: "shield-lock-outline"
                on_tab_press: app.switch_screen("security")

            MDBottomNavigationItem:
                name: "nav_debug"
                text: "Debug"
                icon: "bug-outline"
                on_tab_press: app.switch_screen("debug")
"""


class SecureLLMApp(MDApp):
    _hist_page = 0
    _hist_per_page = 10
    _hist_search = None
    _debug_dirty = False

    def build(self):
        self.title = "Road Safe Scanner"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Blue"
        root = Builder.load_string(KV)
        return root

    def on_start(self):
        _cleanup_tmp_dir()
        logger.info("app start platform=%s base=%s", _kivy_platform, str(BASE_DIR))
        try:
            self.root.ids.screen_manager.current = "road"
        except Exception:
            pass
        Clock.schedule_once(lambda dt: self.gui_model_refresh(), 0.2)
        Clock.schedule_interval(lambda dt: self._debug_auto_refresh(), 0.35)

    def _debug_auto_refresh(self):
        try:
            if self.root.ids.screen_manager.current == "debug" or self._debug_dirty:
                self._debug_dirty = False
                self.gui_debug_refresh()
        except Exception:
            pass

    def switch_screen(self, name: str):
        self.root.ids.screen_manager.current = name
        if name == "debug":
            self.gui_debug_refresh()
        if name == "history":
            self.gui_history_refresh()

    def set_status(self, text: str):
        self.root.ids.status_label.text = text

    def _run_bg(self, work_fn, done_fn=None, err_fn=None):
        def runner():
            try:
                out = work_fn()
                if done_fn:
                    Clock.schedule_once(lambda dt: done_fn(out), 0)
            except Exception as e:
                logger.exception("bg task failed")
                if err_fn:
                    Clock.schedule_once(lambda dt: err_fn(e), 0)
                else:
                    Clock.schedule_once(lambda dt: self.set_status(f"[Error] {e}"), 0)

        threading.Thread(target=runner, daemon=True).start()

    def on_scan(self):
        road_screen = self.root.ids.screen_manager.get_screen("road")
        data = {
            "location": road_screen.ids.loc_field.text.strip() or "unspecified location",
            "road_type": road_screen.ids.road_type_field.text.strip() or "highway",
            "weather": road_screen.ids.weather_field.text.strip() or "clear",
            "traffic": road_screen.ids.traffic_field.text.strip() or "low",
            "obstacles": road_screen.ids.obstacles_field.text.strip() or "none",
            "sensor_notes": road_screen.ids.sensor_notes_field.text.strip() or "none",
        }
        scan_id = uuid.uuid4().hex[:10]
        self.set_status("Scanning road risk...")
        logger.info("road scan req id=%s fields=%s", scan_id, ",".join(sorted(data.keys())))
        threading.Thread(target=self._scan_worker, args=(data, scan_id), daemon=True).start()

    def _scan_worker(self, data: dict, scan_id: str):
        try:
            label, raw = asyncio.run(mobile_run_road_scan(data))
        except Exception as e:
            logger.exception("scan worker failed id=%s", scan_id)
            label, raw = "[Error]", f"[Error: {e}]"
        Clock.schedule_once(lambda dt: self._scan_finish(label, raw, scan_id), 0)

    def _scan_finish(self, label: str, raw: str, scan_id: str):
        road_screen = self.root.ids.screen_manager.get_screen("road")
        try:
            road_screen.ids.risk_wheel.set_level(label)
            road_screen.ids.risk_text.text = f"RISK: {label.upper()}"
        except Exception:
            pass
        road_screen.ids.scan_result.text = label
        self.set_status("")
        logger.info("road scan done id=%s label=%s raw_len=%d", scan_id, label, len(raw or ""))

    def gui_model_refresh(self):
        s = [
            f"Encrypted: {'YES' if ENCRYPTED_MODEL.exists() else 'no'}",
            f"Plain: {'YES' if MODEL_PATH.exists() else 'no'}",
            f"Key: {'YES' if KEY_PATH.exists() else 'no'}",
        ]
        if MODEL_PATH.exists():
            s.append(f"PlainMB: {MODEL_PATH.stat().st_size/1024/1024:.1f}")
        if ENCRYPTED_MODEL.exists():
            s.append(f"EncMB: {ENCRYPTED_MODEL.stat().st_size/1024/1024:.1f}")

        self.root.ids.model_status.text = " | ".join(s)
        self.root.ids.model_progress.value = 0
        logger.info("model refresh %s", " | ".join(s))

    def gui_model_download(self):
        self.set_status("Downloading...")
        self.root.ids.model_progress.value = 0
        url = MODEL_REPO + MODEL_FILE

        def work():
            get_or_create_key()
            last_pct = {"v": -1}
            last_t = {"v": 0.0}

            def cb(done, total):
                if total <= 0:
                    return
                pct = int(done * 100 / total)
                now = time.time()
                if pct != last_pct["v"] and (pct == 100 or now - last_t["v"] > 0.12):
                    last_pct["v"] = pct
                    last_t["v"] = now
                    Clock.schedule_once(lambda dt: setattr(self.root.ids.model_progress, "value", pct), 0)

            sha = download_model_httpx_with_cb(url, MODEL_PATH, progress_cb=cb, timeout=None)
            return sha

        def done(sha):
            self.set_status("")
            self.gui_model_refresh()
            ok = (sha.lower() == EXPECTED_HASH.lower())
            self.root.ids.model_status.text = f"Downloaded SHA={sha} | expected={EXPECTED_HASH} | match={'YES' if ok else 'NO'}"
            logger.info("model downloaded sha=%s match=%s", sha, "YES" if ok else "NO")

        def err(e):
            self.set_status("")
            self.root.ids.model_status.text = f"Download failed: {e}"
            logger.exception("model download failed")

        self._run_bg(work, done, err)

    def gui_model_verify(self):
        if not MODEL_PATH.exists():
            self.root.ids.model_status.text = "No plaintext model."
            return
        self.set_status("Hashing...")

        def work():
            return sha256_file(MODEL_PATH)

        def done(sha):
            self.set_status("")
            ok = (sha.lower() == EXPECTED_HASH.lower())
            self.root.ids.model_status.text = f"Plain SHA={sha} | expected={EXPECTED_HASH} | match={'YES' if ok else 'NO'}"
            logger.info("model sha verify sha=%s match=%s", sha, "YES" if ok else "NO")

        self._run_bg(work, done)

    def gui_model_encrypt(self):
        if not MODEL_PATH.exists():
            self.root.ids.model_status.text = "No plaintext model."
            return
        self.set_status("Encrypting...")

        def work():
            master = get_or_create_key()
            with _MODEL_LOCK:
                encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, _model_key(master))
            return True

        def done(_):
            self.set_status("")
            self.gui_model_refresh()
            self.root.ids.model_status.text = "Encrypted model created."
            logger.info("model encrypt ok")

        def err(e):
            self.set_status("")
            self.root.ids.model_status.text = f"Encrypt failed: {e}"
            logger.exception("model encrypt failed")

        self._run_bg(work, done, err)

    def gui_model_decrypt(self):
        if not ENCRYPTED_MODEL.exists():
            self.root.ids.model_status.text = "No encrypted model."
            return
        self.set_status("Decrypting...")

        def work():
            master = get_or_create_key()
            with _MODEL_LOCK:
                decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, _model_key(master))
            return True

        def done(_):
            self.set_status("")
            self.gui_model_refresh()
            self.root.ids.model_status.text = "Plaintext model present."
            logger.info("model decrypt ok")

        def err(e):
            self.set_status("")
            self.root.ids.model_status.text = f"Decrypt failed: {e}"
            logger.exception("model decrypt failed")

        self._run_bg(work, done, err)

    def gui_model_delete_plain(self):
        with _MODEL_LOCK:
            if not MODEL_PATH.exists():
                self.root.ids.model_status.text = "No plaintext model."
                return
            try:
                MODEL_PATH.unlink()
                self.gui_model_refresh()
                self.root.ids.model_status.text = "Plaintext model deleted."
                logger.info("model plaintext deleted")
            except Exception as e:
                self.root.ids.model_status.text = f"Delete failed: {e}"
                logger.exception("model plaintext delete failed")

    def gui_history_refresh(self):
        self.set_status("Loading history...")
        self.root.ids.history_list.clear_widgets()

        page = self._hist_page
        per_page = self._hist_per_page
        search = self._hist_search

        def work():
            master = get_or_create_key()

            async def job():
                await init_db(master)
                return await fetch_history(master, limit=per_page, offset=page * per_page, search=search)

            return asyncio.run(job())

        def done(rows):
            self.set_status("")
            self.root.ids.history_meta.text = f"Page {self._hist_page+1} | search={self._hist_search or '—'} | rows={len(rows)}"
            if not rows:
                self.root.ids.history_list.add_widget(TwoLineListItem(text="No results", secondary_text="—"))
                return

            for (rid, ts, prompt, resp) in rows:
                self.root.ids.history_list.add_widget(
                    TwoLineListItem(
                        text=f"[{rid}] {ts}",
                        secondary_text=(prompt[:80].replace("\n", " ") + ("…" if len(prompt) > 80 else "")),
                        on_release=lambda item, rid=rid, ts=ts, prompt=prompt, resp=resp: self._history_show_dialog(rid, ts, prompt, resp),
                    )
                )

        def err(e):
            self.set_status("")
            self.root.ids.history_meta.text = f"History error: {e}"
            logger.exception("history refresh failed")

        self._run_bg(work, done, err)

    def _history_show_dialog(self, rid, ts, prompt, resp):
        body = f"[{rid}] {ts}\n\nQ:\n{prompt}\n\nA:\n{resp}"
        dlg = MDDialog(
            title="History Entry",
            text=body,
            buttons=[MDFlatButton(text="Close", on_release=lambda x: dlg.dismiss())],
        )
        dlg.open()

    def gui_history_next(self):
        self._hist_page += 1
        self.gui_history_refresh()

    def gui_history_prev(self):
        if self._hist_page > 0:
            self._hist_page -= 1
        self.gui_history_refresh()

    def gui_history_search(self):
        s = self.root.ids.history_search.text.strip()
        self._hist_search = s or None
        self._hist_page = 0
        self.gui_history_refresh()

    def gui_history_clear(self):
        self.root.ids.history_search.text = ""
        self._hist_search = None
        self._hist_page = 0
        self.gui_history_refresh()

    def _gui_rekey_common(self, make_new_master_key_fn: Callable[[], bytes]):
        self.set_status("Rekeying...")
        self.root.ids.rekey_progress.value = 5
        self.root.ids.rekey_status.text = "Preparing..."

        def work():
            with _MODEL_LOCK:
                old_master = get_or_create_key()
                old_mk = _model_key(old_master)
                old_dk = _db_key(old_master)

                tmp_model_plain = _tmp_path("model_rekey", ".gguf")
                tmp_db_plain = _tmp_path("db_rekey", ".db")

                new_enc_model_tmp = ENCRYPTED_MODEL.with_suffix(ENCRYPTED_MODEL.suffix + f".rekey.{uuid.uuid4().hex}.tmp")
                new_db_tmp = DB_PATH.with_suffix(DB_PATH.suffix + f".rekey.{uuid.uuid4().hex}.tmp")

                try:
                    self._rekey_ui(10, "Decrypting...")

                    if ENCRYPTED_MODEL.exists():
                        decrypt_file(ENCRYPTED_MODEL, tmp_model_plain, old_mk)

                    if DB_PATH.exists():
                        with _CRYPTO_LOCK:
                            pt = aes_decrypt(DB_PATH.read_bytes(), old_dk)
                            _atomic_write_bytes(tmp_db_plain, pt)

                    self._rekey_ui(45, "Generating new key...")

                    new_master = make_new_master_key_fn()
                    new_mk = _model_key(new_master)
                    new_dk = _db_key(new_master)

                    self._rekey_ui(60, "Re-encrypting...")

                    if tmp_model_plain.exists():
                        encrypt_file(tmp_model_plain, new_enc_model_tmp, new_mk)

                    if tmp_db_plain.exists():
                        with _CRYPTO_LOCK:
                            encdb = aes_encrypt(tmp_db_plain.read_bytes(), new_dk)
                        _atomic_write_bytes(new_db_tmp, encdb)

                    self._rekey_ui(85, "Committing...")

                    if new_enc_model_tmp.exists():
                        new_enc_model_tmp.replace(ENCRYPTED_MODEL)
                    if new_db_tmp.exists():
                        new_db_tmp.replace(DB_PATH)

                    with _CRYPTO_LOCK:
                        _store_wrapped_key(new_master)

                    return True
                finally:
                    for p in [tmp_model_plain, tmp_db_plain, new_enc_model_tmp, new_db_tmp]:
                        try:
                            p.unlink(missing_ok=True)
                        except Exception:
                            pass
                    _cleanup_tmp_dir()

        def done(_):
            self.set_status("")
            self.root.ids.rekey_progress.value = 100
            self.root.ids.rekey_status.text = "Rekey complete."
            self.gui_model_refresh()
            logger.info("rekey complete")

        def err(e):
            self.set_status("")
            self.root.ids.rekey_progress.value = 0
            self.root.ids.rekey_status.text = f"Rekey failed: {e}"
            logger.exception("rekey failed")

        self._run_bg(work, done, err)

    def _rekey_ui(self, pct: int, text: str):
        try:
            Clock.schedule_once(lambda dt: setattr(self.root.ids.rekey_progress, "value", int(pct)), 0)
            Clock.schedule_once(lambda dt: setattr(self.root.ids.rekey_status, "text", str(text)), 0)
        except Exception:
            pass

    def gui_rekey_random(self):
        def make_new_master():
            return AESGCM.generate_key(256)
        self._gui_rekey_common(make_new_master)

    def gui_rekey_passphrase_dialog(self):
        box = MDBoxLayout(orientation="vertical", spacing="12dp", padding="12dp", adaptive_height=True)
        pass_field = MDTextField(hint_text="Passphrase", password=True)
        pass2_field = MDTextField(hint_text="Confirm passphrase", password=True)
        box.add_widget(pass_field)
        box.add_widget(pass2_field)

        dlg = MDDialog(
            title="Passphrase Rekey",
            type="custom",
            content_cls=box,
            buttons=[
                MDFlatButton(text="Cancel", on_release=lambda x: dlg.dismiss()),
                MDFlatButton(text="Rekey", on_release=lambda x: self._do_pass_rekey(dlg, pass_field.text, pass2_field.text)),
            ],
        )
        dlg.open()

    def _do_pass_rekey(self, dlg, pw1: str, pw2: str):
        if (pw1 or "") != (pw2 or "") or not (pw1 or "").strip():
            self.root.ids.rekey_status.text = "Passphrase mismatch or empty."
            logger.warning("pass rekey mismatch/empty")
            return

        dlg.dismiss()
        pw = pw1.strip()

        def make_new_master():
            _salt, derived = derive_key_from_passphrase(pw)
            return derived

        self._gui_rekey_common(make_new_master)

    def gui_debug_refresh(self):
        try:
            meta = f"lines={len(_RING.text().splitlines())} | file={'YES' if LOG_PATH.exists() else 'no'} | path={str(LOG_PATH)}"
            self.root.ids.debug_meta.text = meta
            self.root.ids.debug_text.text = _RING.text() or "—"
        except Exception:
            pass

    def gui_debug_clear(self):
        _RING.clear()
        try:
            with _LOG_LOCK:
                if LOG_PATH.exists():
                    LOG_PATH.unlink()
        except Exception:
            pass
        self.gui_debug_refresh()

    def gui_debug_emit_test(self):
        logger.info("debug emit test %s", uuid.uuid4().hex[:10])
        try:
            raise RuntimeError("debug test exception")
        except Exception:
            logger.exception("debug test exception")


if __name__ == "__main__":
    SecureLLMApp().run()
