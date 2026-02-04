
import os, sys, time, json, hashlib, asyncio, threading, httpx, aiosqlite, math, random, re, uuid, tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Tuple, Callable, Dict
from contextlib import contextmanager
from threading import RLock
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from llama_cpp import Llama

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
from kivy.uix.video import Video
from kivy.animation import Animation
from kivy.metrics import dp
from kivy.graphics import Color, Line, RoundedRectangle, Rectangle
from kivy.graphics.texture import Texture
from kivy.properties import NumericProperty, StringProperty, ListProperty
from kivymd.app import MDApp
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDFlatButton, MDRaisedButton
from kivymd.uix.list import TwoLineListItem
from kivymd.uix.textfield import MDTextField
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.toolbar import MDTopAppBar

try:
    from jnius import autoclass
except Exception:
    autoclass = None
try:
    from android.permissions import request_permissions, Permission
except Exception:
    request_permissions = None
    Permission = None

if hasattr(Window, "size"):
    Window.size = (420, 760)

MODEL_REPO = "https://huggingface.co/tensorblock/llama3-small-GGUF/resolve/main/"
MODEL_FILE = "llama3-small-Q3_K_M.gguf"
MODELS_DIR = Path("models")
MODEL_PATH = MODELS_DIR / MODEL_FILE
ENCRYPTED_MODEL = MODEL_PATH.with_suffix(MODEL_PATH.suffix + ".aes")
DB_PATH = Path("chat_history.db.aes")
KEY_PATH = Path(".enc_key")
EXPECTED_HASH = "8e4f4856fb84bafb895f1eb08e6c03e4be613ead2d942f91561aeac742a619aa"
MEDIA_DIR = Path("media")
CHUNKS_DIR = MEDIA_DIR / "chunks"
CHUNK_SECONDS = 30
CHUNK_KEEP_LIMIT = 2000
MODELS_DIR.mkdir(parents=True, exist_ok=True)
CHUNKS_DIR.mkdir(parents=True, exist_ok=True)

_CRYPTO_LOCK = RLock()
_MODEL_LOCK = RLock()
_MODEL_USERS = 0

def _atomic_write_bytes(path: Path, data: bytes):
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}")
    tmp.write_bytes(data)
    tmp.replace(path)

def _tmp_path(prefix: str, suffix: str) -> Path:
    base = Path(tempfile.gettempdir()) if tempfile.gettempdir() else Path(".")
    return base / f"{prefix}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}{suffix}"

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data, None)

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce, ct = data[:12], data[12:]
    return aes.decrypt(nonce, ct, None)

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def get_or_create_key() -> bytes:
    with _CRYPTO_LOCK:
        if KEY_PATH.exists():
            d = KEY_PATH.read_bytes()
            if len(d) >= 48:
                return d[16:48]
            return d[:32]
        key = AESGCM.generate_key(256)
        _atomic_write_bytes(KEY_PATH, key)
        return key

def derive_key_from_passphrase(pw: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf_der = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    derived = kdf_der.derive(pw.encode("utf-8"))
    return salt, derived

def download_model_httpx_with_cb(url: str, dest: Path, progress_cb: Optional[Callable[[int, int], None]] = None, timeout=None) -> str:
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

def encrypt_file(src: Path, dest: Path, key: bytes):
    with _CRYPTO_LOCK:
        data = src.read_bytes()
        enc = aes_encrypt(data, key)
        _atomic_write_bytes(dest, enc)

def decrypt_file(src: Path, dest: Path, key: bytes):
    with _CRYPTO_LOCK:
        enc = src.read_bytes()
        data = aes_decrypt(enc, key)
        tmp = dest.with_suffix(dest.suffix + f".dec.{uuid.uuid4().hex}")
        tmp.write_bytes(data)
        tmp.replace(dest)

async def init_db(key: bytes):
    with _CRYPTO_LOCK:
        if DB_PATH.exists():
            return
        tmp_plain = _tmp_path("chat_init", ".db")
        try:
            async with aiosqlite.connect(str(tmp_plain)) as db:
                await db.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, prompt TEXT, response TEXT)")
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, kind TEXT, severity TEXT, details TEXT, chain_hash TEXT)"
                )
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS security_state (state_key TEXT PRIMARY KEY, state_value TEXT)"
                )
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS media_chunks (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, path TEXT, duration INTEGER, signature TEXT, alert INTEGER)"
                )
                await db.commit()
            enc = aes_encrypt(tmp_plain.read_bytes(), key)
            _atomic_write_bytes(DB_PATH, enc)
        finally:
            try:
                tmp_plain.unlink(missing_ok=True)
            except Exception:
                pass

async def ensure_db_schema(key: bytes):
    with _CRYPTO_LOCK:
        if not DB_PATH.exists():
            await init_db(key)
            return
        tmp_plain = _tmp_path("db_schema", ".db")
        try:
            decrypt_file(DB_PATH, tmp_plain, key)
            async with aiosqlite.connect(str(tmp_plain)) as db:
                await db.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, prompt TEXT, response TEXT)")
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, kind TEXT, severity TEXT, details TEXT, chain_hash TEXT)"
                )
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS security_state (state_key TEXT PRIMARY KEY, state_value TEXT)"
                )
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS media_chunks (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, path TEXT, duration INTEGER, signature TEXT, alert INTEGER)"
                )
                await db.commit()
            enc = aes_encrypt(tmp_plain.read_bytes(), key)
            _atomic_write_bytes(DB_PATH, enc)
        finally:
            try:
                tmp_plain.unlink(missing_ok=True)
            except Exception:
                pass

async def log_interaction(prompt: str, response: str, key: bytes):
    with _CRYPTO_LOCK:
        if not DB_PATH.exists():
            await init_db(key)
        tmp_plain = _tmp_path("chat_work", ".db")
        try:
            decrypt_file(DB_PATH, tmp_plain, key)
            async with aiosqlite.connect(str(tmp_plain)) as db:
                await db.execute(
                    "INSERT INTO history (timestamp, prompt, response) VALUES (?, ?, ?)",
                    (time.strftime("%Y-%m-%d %H:%M:%S"), prompt, response),
                )
                await db.commit()
            enc = aes_encrypt(tmp_plain.read_bytes(), key)
            _atomic_write_bytes(DB_PATH, enc)
        finally:
            try:
                tmp_plain.unlink(missing_ok=True)
            except Exception:
                pass

async def fetch_history(key: bytes, limit: int = 20, offset: int = 0, search: Optional[str] = None):
    with _CRYPTO_LOCK:
        if not DB_PATH.exists():
            await init_db(key)
        tmp_plain = _tmp_path("chat_read", ".db")
        rows = []
        try:
            decrypt_file(DB_PATH, tmp_plain, key)
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
            enc = aes_encrypt(tmp_plain.read_bytes(), key)
            _atomic_write_bytes(DB_PATH, enc)
        finally:
            try:
                tmp_plain.unlink(missing_ok=True)
            except Exception:
                pass
        return rows

async def fetch_security_state(key: bytes, state_key: str) -> Optional[str]:
    with _CRYPTO_LOCK:
        if not DB_PATH.exists():
            await init_db(key)
        tmp_plain = _tmp_path("sec_state_read", ".db")
        try:
            decrypt_file(DB_PATH, tmp_plain, key)
            async with aiosqlite.connect(str(tmp_plain)) as db:
                async with db.execute(
                    "SELECT state_value FROM security_state WHERE state_key = ?",
                    (state_key,),
                ) as cur:
                    row = await cur.fetchone()
            enc = aes_encrypt(tmp_plain.read_bytes(), key)
            _atomic_write_bytes(DB_PATH, enc)
            return row[0] if row else None
        finally:
            try:
                tmp_plain.unlink(missing_ok=True)
            except Exception:
                pass

async def upsert_security_state(key: bytes, state_key: str, state_value: str):
    with _CRYPTO_LOCK:
        if not DB_PATH.exists():
            await init_db(key)
        tmp_plain = _tmp_path("sec_state_write", ".db")
        try:
            decrypt_file(DB_PATH, tmp_plain, key)
            async with aiosqlite.connect(str(tmp_plain)) as db:
                await db.execute(
                    "INSERT INTO security_state (state_key, state_value) VALUES (?, ?) ON CONFLICT(state_key) DO UPDATE SET state_value = excluded.state_value",
                    (state_key, state_value),
                )
                await db.commit()
            enc = aes_encrypt(tmp_plain.read_bytes(), key)
            _atomic_write_bytes(DB_PATH, enc)
        finally:
            try:
                tmp_plain.unlink(missing_ok=True)
            except Exception:
                pass

async def append_security_event(key: bytes, kind: str, severity: str, details: str):
    with _CRYPTO_LOCK:
        if not DB_PATH.exists():
            await init_db(key)
        tmp_plain = _tmp_path("sec_event", ".db")
        try:
            decrypt_file(DB_PATH, tmp_plain, key)
            async with aiosqlite.connect(str(tmp_plain)) as db:
                async with db.execute(
                    "SELECT chain_hash FROM security_events ORDER BY id DESC LIMIT 1"
                ) as cur:
                    row = await cur.fetchone()
                prev_hash = row[0] if row else "0" * 64
                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                payload = f"{prev_hash}|{stamp}|{kind}|{severity}|{details}"
                chain_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                await db.execute(
                    "INSERT INTO security_events (timestamp, kind, severity, details, chain_hash) VALUES (?, ?, ?, ?, ?)",
                    (stamp, kind, severity, details, chain_hash),
                )
                await db.commit()
            enc = aes_encrypt(tmp_plain.read_bytes(), key)
            _atomic_write_bytes(DB_PATH, enc)
        finally:
            try:
                tmp_plain.unlink(missing_ok=True)
            except Exception:
                pass

async def append_media_chunk(key: bytes, path: str, duration: int, signature: str, alert: bool):
    with _CRYPTO_LOCK:
        if not DB_PATH.exists():
            await init_db(key)
        tmp_plain = _tmp_path("media_chunk", ".db")
        try:
            decrypt_file(DB_PATH, tmp_plain, key)
            async with aiosqlite.connect(str(tmp_plain)) as db:
                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                await db.execute(
                    "INSERT INTO media_chunks (timestamp, path, duration, signature, alert) VALUES (?, ?, ?, ?, ?)",
                    (stamp, path, duration, signature, 1 if alert else 0),
                )
                await db.commit()
            enc = aes_encrypt(tmp_plain.read_bytes(), key)
            _atomic_write_bytes(DB_PATH, enc)
        finally:
            try:
                tmp_plain.unlink(missing_ok=True)
            except Exception:
                pass

async def fetch_media_chunks(key: bytes, alert_only: bool = False, limit: int = 30, offset: int = 0):
    with _CRYPTO_LOCK:
        if not DB_PATH.exists():
            await init_db(key)
        tmp_plain = _tmp_path("media_chunks", ".db")
        rows = []
        try:
            decrypt_file(DB_PATH, tmp_plain, key)
            async with aiosqlite.connect(str(tmp_plain)) as db:
                if alert_only:
                    query = "SELECT id,timestamp,path,duration,signature,alert FROM media_chunks WHERE alert = 1 ORDER BY id DESC LIMIT ? OFFSET ?"
                    args = (limit, offset)
                else:
                    query = "SELECT id,timestamp,path,duration,signature,alert FROM media_chunks ORDER BY id DESC LIMIT ? OFFSET ?"
                    args = (limit, offset)
                async with db.execute(query, args) as cur:
                    async for r in cur:
                        rows.append(r)
            enc = aes_encrypt(tmp_plain.read_bytes(), key)
            _atomic_write_bytes(DB_PATH, enc)
        finally:
            try:
                tmp_plain.unlink(missing_ok=True)
            except Exception:
                pass
        return rows

def load_llama_model_blocking(model_path: Path) -> Llama:
    return Llama(model_path=str(model_path), n_ctx=2048, n_threads=max(2, (os.cpu_count() or 4) // 2))

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
            possible = ["/sys/devices/virtual/thermal/thermal_zone0/temp", "/sys/class/hwmon/hwmon0/temp1_input"]
            for p in possible:
                try:
                    with open(p, "r") as f:
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
    core_ok = all(x is not None for x in (cpu, mem, load1, proc))
    if not core_ok:
        raise RuntimeError("Unable to obtain core system metrics")
    cpu = float(max(0.0, min(1.0, cpu)))
    mem = float(max(0.0, min(1.0, mem)))
    load1 = float(max(0.0, min(1.0, load1)))
    proc = float(max(0.0, min(1.0, proc)))
    temp = float(max(0.0, min(1.0, temp))) if temp is not None else 0.0
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
    return (float(max(0.0, min(1.0, r))), float(max(0.0, min(1.0, g))), float(max(0.0, min(1.0, b))))

def _normalize_rgb(values: Tuple[float, float, float]) -> Tuple[float, float, float]:
    r, g, b = values
    max_val = max(r, g, b)
    if max_val > 1.5:
        r, g, b = r / 255.0, g / 255.0, b / 255.0
    return (
        float(max(0.0, min(1.0, r))),
        float(max(0.0, min(1.0, g))),
        float(max(0.0, min(1.0, b))),
    )

def parse_color_samples(text: str) -> Dict[str, Tuple[float, float, float]]:
    if not text:
        return {}
    if text.strip().lower() in {"none", "n/a", "na", "null"}:
        return {}
    entries = [e.strip() for e in re.split(r"[\n;|]+", text) if e.strip()]
    results: Dict[str, Tuple[float, float, float]] = {}
    auto_idx = 1
    for entry in entries:
        label = None
        value = entry
        if ":" in entry or "=" in entry:
            parts = re.split(r"[:=]", entry, maxsplit=1)
            label = parts[0].strip() or None
            value = parts[1].strip() if len(parts) > 1 else ""
        rgb: Optional[Tuple[float, float, float]] = None
        if re.fullmatch(r"#?[0-9a-fA-F]{6}", value or ""):
            hex_value = value.lstrip("#")
            rgb = (
                int(hex_value[0:2], 16) / 255.0,
                int(hex_value[2:4], 16) / 255.0,
                int(hex_value[4:6], 16) / 255.0,
            )
        else:
            nums = [float(x) for x in re.findall(r"[0-9.]+", value)]
            if len(nums) >= 3:
                rgb = _normalize_rgb((nums[0], nums[1], nums[2]))
        if rgb is None:
            continue
        if not label:
            label = f"color_{auto_idx}"
        base_label = label
        suffix = 1
        while label in results:
            suffix += 1
            label = f"{base_label}_{suffix}"
        results[label] = _normalize_rgb(rgb)
        auto_idx += 1
    return results

def compute_color_change_metrics(alarm_text: str, settle_text: str) -> Dict[str, object]:
    alarm = parse_color_samples(alarm_text)
    settle = parse_color_samples(settle_text)
    labels = sorted(set(alarm.keys()) | set(settle.keys()))
    changes = []
    total_delta = 0.0
    max_delta = 0.0
    changed_labels = []
    for label in labels:
        a = alarm.get(label, (0.0, 0.0, 0.0))
        s = settle.get(label, (0.0, 0.0, 0.0))
        delta = math.sqrt(((a[0] - s[0]) ** 2 + (a[1] - s[1]) ** 2 + (a[2] - s[2]) ** 2) / 3.0)
        changes.append({"label": label, "alarm": a, "settle": s, "delta": delta})
        total_delta += delta
        max_delta = max(max_delta, delta)
        if delta >= 0.08 or label not in alarm or label not in settle:
            changed_labels.append((label, delta))
    avg_delta = total_delta / max(1, len(labels))
    change_ratio = len(changed_labels) / max(1, len(labels))
    return {
        "labels": labels,
        "changes": changes,
        "changed_labels": changed_labels,
        "avg_delta": float(avg_delta),
        "max_delta": float(max_delta),
        "change_ratio": float(change_ratio),
        "alarm_count": len(alarm),
        "settle_count": len(settle),
    }

def build_color_change_summary(metrics: Dict[str, object]) -> str:
    labels = metrics.get("labels") or []
    if not labels:
        return "color_shift=none"
    changed = metrics.get("changed_labels") or []
    changed_text = ", ".join([f"{label}({delta:.2f})" for label, delta in changed]) or "none"
    avg_delta = metrics.get("avg_delta", 0.0)
    max_delta = metrics.get("max_delta", 0.0)
    ratio = metrics.get("change_ratio", 0.0)
    return f"color_shift=changed[{changed_text}] avg={avg_delta:.2f} max={max_delta:.2f} ratio={ratio:.2f}"

def color_features_to_rgb(metrics: Dict[str, object]) -> Tuple[float, float, float]:
    avg_delta = float(metrics.get("avg_delta", 0.0))
    max_delta = float(metrics.get("max_delta", 0.0))
    ratio = float(metrics.get("change_ratio", 0.0))
    return _normalize_rgb((avg_delta, max_delta, ratio))

def build_color_rag_context(metrics: Dict[str, object], entropy_score: float) -> str:
    avg_delta = float(metrics.get("avg_delta", 0.0))
    max_delta = float(metrics.get("max_delta", 0.0))
    ratio = float(metrics.get("change_ratio", 0.0))
    signals = [
        {
            "name": "low_shift",
            "when": avg_delta < 0.08 and max_delta < 0.12 and ratio < 0.25,
            "guidance": "Color field stable; treat as baseline activity unless other indicators spike.",
        },
        {
            "name": "localized_shift",
            "when": avg_delta < 0.14 and max_delta >= 0.12 and ratio < 0.45,
            "guidance": "Localized color change; possible motion at a boundary or partial occlusion.",
        },
        {
            "name": "broad_shift",
            "when": avg_delta >= 0.14 or ratio >= 0.45,
            "guidance": "Broad color change; likely movement, lighting disturbance, or tamper event.",
        },
        {
            "name": "entropy_escalation",
            "when": entropy_score >= 0.7,
            "guidance": "High color entropy; increase risk posture unless corroborated as benign.",
        },
    ]
    applicable = [s["guidance"] for s in signals if s["when"]]
    if not applicable:
        applicable = ["Color change is ambiguous; keep risk neutral without other signals."]
    summary = f"avg_delta={avg_delta:.2f} max_delta={max_delta:.2f} ratio={ratio:.2f} entropy={entropy_score:.2f}"
    return " | ".join([summary] + applicable)

def normalize_risk_label(text: str, fallback: str = "Medium") -> str:
    cleaned = (text or "").strip()
    if not cleaned:
        return fallback
    tokens = re.findall(r"[A-Za-z]+", cleaned.lower())
    for token in tokens:
        if token in {"low", "medium", "high"}:
            return token.capitalize()
    lowered = cleaned.lower()
    if "low" in lowered:
        return "Low"
    if "medium" in lowered:
        return "Medium"
    if "high" in lowered:
        return "High"
    return fallback

def risk_level_from_score(score: float) -> str:
    if score >= 0.7:
        return "High"
    if score >= 0.45:
        return "Medium"
    return "Low"

def combine_risk_labels(primary: str, secondary: str) -> str:
    ranking = {"Low": 0, "Medium": 1, "High": 2}
    p = ranking.get(primary, 1)
    s = ranking.get(secondary, 1)
    return primary if p >= s else secondary

def pennylane_color_shift_risk(features: Tuple[float, float, float], shots: int = 256) -> float:
    a, b, c = features
    if qml is None or pnp is None:
        seed = int((int(a * 255) << 16) | (int(b * 255) << 8) | int(c * 255))
        random.seed(seed)
        base = (0.5 * a + 0.3 * b + 0.2 * c)
        noise = (random.random() - 0.5) * 0.06
        return float(max(0.0, min(1.0, base + noise)))
    dev = qml.device("default.qubit", wires=3, shots=shots)
    @qml.qnode(dev)
    def circuit(x, y, z):
        qml.RX(x * math.pi, wires=0)
        qml.RY(y * math.pi, wires=1)
        qml.RZ(z * math.pi, wires=2)
        qml.CNOT(wires=[0, 1])
        qml.CZ(wires=[1, 2])
        qml.RY((x + y) * math.pi / 2, wires=0)
        qml.RX((y + z) * math.pi / 2, wires=2)
        return qml.expval(qml.PauliZ(0)), qml.expval(qml.PauliZ(1)), qml.expval(qml.PauliZ(2))
    try:
        ev0, ev1, ev2 = circuit(float(a), float(b), float(c))
        combined = ((ev0 + 1.0) / 2.0 * 0.5 + (ev1 + 1.0) / 2.0 * 0.3 + (ev2 + 1.0) / 2.0 * 0.2)
        score = 1.0 / (1.0 + math.exp(-5.0 * (combined - 0.5)))
        return float(max(0.0, min(1.0, score)))
    except Exception:
        return float(max(0.0, min(1.0, (a + b + c) / 3.0)))

def forecast_risk_series(base_score: float, hours: int, seed: int) -> List[str]:
    labels = []
    for hour in range(1, hours + 1):
        drift = math.sin((hour + seed) * 0.35) * 0.07 + math.cos((hour + seed) * 0.07) * 0.03
        decay = math.exp(-hour / 240.0)
        score = base_score * decay + (1.0 - decay) * 0.35 + drift
        score = float(max(0.0, min(1.0, score)))
        labels.append(risk_level_from_score(score))
    return labels

def summarize_forecast(labels: List[str], hours: int) -> str:
    counts = {"Low": 0, "Medium": 0, "High": 0}
    for label in labels:
        counts[label] = counts.get(label, 0) + 1
    head = ", ".join(labels[:min(6, len(labels))])
    tail = ", ".join(labels[-min(6, len(labels)):]) if labels else ""
    return f"{hours}h forecast L={counts['Low']} M={counts['Medium']} H={counts['High']} | start[{head}] end[{tail}]"

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
    return [t for t in re.findall(r"[A-Za-z0-9_\-]+", text.lower())]

def llm_detection_signal(text: str) -> Tuple[str, float]:
    toks = _simple_tokenize(text)
    if not toks:
        return "low", 0.0
    uniq = len(set(toks))
    rep_ratio = 1.0 - (uniq / max(1, len(toks)))
    avg_len = sum(len(t) for t in toks) / max(1, len(toks))
    ai_markers = sum(1 for t in toks if t in {"model", "llm", "assistant", "prompt", "temperature", "token"})
    score = (rep_ratio * 0.6) + (min(avg_len / 8.0, 1.0) * 0.2) + (min(ai_markers / 4.0, 1.0) * 0.2)
    score = max(0.0, min(1.0, score))
    if score >= 0.7:
        return "high", score
    if score >= 0.4:
        return "medium", score
    return "low", score

def frame_signature_hash(signature: str) -> str:
    cleaned = (signature or "").strip().encode("utf-8")
    return hashlib.sha256(cleaned).hexdigest()

def is_android() -> bool:
    return bool(os.environ.get("ANDROID_ARGUMENT") or os.environ.get("ANDROID_BOOTLOGO"))

def compute_chunk_signature(path: Path) -> str:
    h = hashlib.sha256()
    try:
        size = path.stat().st_size
        h.update(str(size).encode("utf-8"))
        with path.open("rb") as f:
            head = f.read(4096)
            if head:
                h.update(head)
            if size > 4096:
                f.seek(max(0, size - 4096))
                tail = f.read(4096)
                if tail:
                    h.update(tail)
    except Exception:
        h.update(os.urandom(16))
    return h.hexdigest()

class AndroidRecorder:
    def __init__(self):
        self._recorder = None
        self._output_path = None
    def start(self, output_path: str):
        if autoclass is None:
            raise RuntimeError("pyjnius not available")
        MediaRecorder = autoclass("android.media.MediaRecorder")
        CamcorderProfile = autoclass("android.media.CamcorderProfile")
        recorder = MediaRecorder()
        recorder.setAudioSource(MediaRecorder.AudioSource.MIC)
        recorder.setVideoSource(MediaRecorder.VideoSource.CAMERA)
        profile = CamcorderProfile.get(CamcorderProfile.QUALITY_480P)
        recorder.setOutputFormat(profile.fileFormat)
        recorder.setVideoEncoder(profile.videoCodec)
        recorder.setAudioEncoder(profile.audioCodec)
        recorder.setVideoEncodingBitRate(profile.videoBitRate)
        recorder.setVideoFrameRate(profile.videoFrameRate)
        recorder.setVideoSize(profile.videoFrameWidth, profile.videoFrameHeight)
        recorder.setAudioEncodingBitRate(profile.audioBitRate)
        recorder.setAudioSamplingRate(profile.audioSampleRate)
        recorder.setOutputFile(output_path)
        recorder.prepare()
        recorder.start()
        self._recorder = recorder
        self._output_path = output_path
    def stop(self):
        if self._recorder is None:
            return
        try:
            self._recorder.stop()
        except Exception:
            pass
        try:
            self._recorder.reset()
            self._recorder.release()
        except Exception:
            pass
        self._recorder = None
        return self._output_path

def punkd_analyze(prompt_text: str, top_n: int = 12) -> Dict[str, float]:
    toks = _simple_tokenize(prompt_text)
    freq = {}
    for t in toks:
        freq[t] = freq.get(t, 0) + 1
    hazard_boost = {"ice": 2.0, "wet": 1.8, "snow": 2.0, "flood": 2.0, "construction": 1.8, "pedestrian": 1.8, "debris": 1.8, "animal": 1.5, "stall": 1.4, "fog": 1.6}
    scored = {}
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

def chunked_generate(llm: Llama, prompt: str, max_total_tokens: int = 256, chunk_tokens: int = 64, base_temperature: float = 0.2, punkd_profile: str = "balanced", streaming_callback: Optional[Callable[[str], None]] = None) -> str:
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
                text = out.get("text", "") if isinstance(out, dict) else ""
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

def build_security_scanner_prompt(data: dict, include_system_entropy: bool = True) -> str:
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
        "You are an active security scanner AI running 24/7 for live site monitoring.\n"
        "Analyze the provided security context and determine the overall risk level.\n"
        "Your reply must be only one word: Low, Medium, or High.\n\n"
        "[tuning]\n"
        "Security context:\n"
        f"Site: {data.get('site','unspecified site')}\n"
        f"Zone: {data.get('zone','unknown')}\n"
        f"Human activity: {data.get('human_activity','unknown')}\n"
        f"Camera notes: {data.get('camera_notes','none')}\n"
        f"Access control: {data.get('access_control','unknown')}\n"
        f"Frame signature: {data.get('frame_signature','none')}\n"
        f"Movement alarm colors: {data.get('movement_alarm_colors','none')}\n"
        f"Settle state colors: {data.get('settle_colors','none')}\n"
        f"Color change summary: {data.get('color_change_summary','none')}\n"
        f"Quantum color risk: {data.get('quantum_color_risk','unknown')}\n"
        f"Color RAG context: {data.get('color_rag_context','none')}\n"
        f"LLM detection notes: {data.get('llm_detection','none')}\n"
        f"Tamper evidence: {data.get('tamper_evidence','none')}\n"
        f"{metrics_line}\n"
        f"Quantum State: {entropy_text}\n"
        "[/tuning]\n\n"
        "Follow these strict rules when forming your decision:\n"
        "- Think through all scene factors internally but do not show reasoning.\n"
        "- Evaluate human activity, access anomalies, and frame-change signals holistically.\n"
        "- Optionally use the system entropic signal to bias your internal confidence slightly.\n"
        "- Choose only one risk level that best fits the entire situation.\n"
        "- Output exactly one word, with no punctuation or labels.\n"
        "- The valid outputs are only: Low, Medium, High.\n\n"
        "[action]\n"
        "1) Normalize sensor inputs to comparable scales.\n"
        "2) Flag frame-change or tamper indicators; bias toward higher risk.\n"
        "3) Map security risk cues -> discrete label using conservative thresholds.\n"
        "4) PUNKD: detect key tokens and locally adjust attention/temperature slightly to focus decisions.\n"
        "5) Do not output internal reasoning or diagnostics; only return the single-word label.\n"
        "[/action]\n\n"
        "[replytemplate]\n"
        "Low | Medium | High\n"
        "[/replytemplate]"
    )

async def mobile_ensure_init() -> bytes:
    key = get_or_create_key()
    try:
        await ensure_db_schema(key)
    except Exception:
        pass
    return key

@contextmanager
def acquire_plain_model(key: bytes):
    global _MODEL_USERS
    with _MODEL_LOCK:
        if ENCRYPTED_MODEL.exists() and not MODEL_PATH.exists():
            decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, key)
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
                    encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, key)
                    MODEL_PATH.unlink(missing_ok=True)
                except Exception:
                    pass

async def mobile_run_chat(prompt: str) -> str:
    key = await mobile_ensure_init()
    try:
        with acquire_plain_model(key) as model_path:
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor(max_workers=1) as ex:
                try:
                    llm = await loop.run_in_executor(ex, load_llama_model_blocking, model_path)
                except Exception as e:
                    return f"[Error loading model: {e}]"
                def gen(p):
                    out = llm(p, max_tokens=256, temperature=0.7)
                    text = ""
                    if isinstance(out, dict):
                        try:
                            text = out.get("choices", [{"text": ""}])[0].get("text", "")
                        except Exception:
                            text = out.get("text", "")
                    else:
                        text = str(out)
                    text = (text or "").strip()
                    text = text.replace("You are a helpful AI assistant named SmolLM, trained by Hugging Face", "").strip()
                    return text
                result = await loop.run_in_executor(ex, gen, prompt)
                try:
                    await log_interaction(prompt, result, key)
                except Exception:
                    pass
                try:
                    del llm
                except Exception:
                    pass
                return result
    except FileNotFoundError:
        return "[Model not found. Place or download the GGUF model on device.]"

async def mobile_run_security_scan(data: dict) -> Tuple[str, str, Dict[str, str]]:
    key = await mobile_ensure_init()
    color_metrics = compute_color_change_metrics(
        data.get("movement_alarm_colors", ""),
        data.get("settle_colors", ""),
    )
    color_summary = build_color_change_summary(color_metrics)
    color_rgb = color_features_to_rgb(color_metrics)
    color_entropy = pennylane_entropic_score(color_rgb)
    color_rag_context = build_color_rag_context(color_metrics, color_entropy)
    quantum_score = pennylane_color_shift_risk(
        (
            float(color_metrics.get("avg_delta", 0.0)),
            float(color_metrics.get("max_delta", 0.0)),
            float(color_metrics.get("change_ratio", 0.0)),
        )
    )
    quantum_label = risk_level_from_score(quantum_score)
    data = dict(data)
    data["color_change_summary"] = color_summary
    data["quantum_color_risk"] = f"{quantum_label} ({quantum_score:.2f})"
    data["color_rag_context"] = color_rag_context
    prompt = build_security_scanner_prompt(data, include_system_entropy=True)
    frame_sig = data.get("frame_signature", "")
    frame_hash = frame_signature_hash(frame_sig) if frame_sig else ""
    prior_hash = ""
    frame_changed = False
    if frame_hash:
        try:
            prior_hash = await fetch_security_state(key, "last_frame_hash") or ""
            frame_changed = bool(prior_hash and prior_hash != frame_hash)
            await upsert_security_state(key, "last_frame_hash", frame_hash)
        except Exception:
            frame_changed = False
    llm_level, llm_score = llm_detection_signal(data.get("llm_detection", ""))
    tamper_note = data.get("tamper_evidence", "none")
    seed = int(hashlib.sha256(color_summary.encode("utf-8")).hexdigest(), 16) % 997
    forecast_47 = forecast_risk_series(quantum_score, 47, seed)
    forecast_700 = forecast_risk_series(quantum_score, 700, seed + 37)
    forecast_47_summary = summarize_forecast(forecast_47, 47)
    forecast_700_summary = summarize_forecast(forecast_700, 700)
    try:
        with acquire_plain_model(key) as model_path:
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor(max_workers=1) as ex:
                try:
                    llm = await loop.run_in_executor(ex, load_llama_model_blocking, model_path)
                except Exception as e:
                    return "[Error]", f"[Error loading model: {e}]"
                def run_chunked():
                    return chunked_generate(llm=llm, prompt=prompt, max_total_tokens=256, chunk_tokens=64, base_temperature=0.18, punkd_profile="balanced", streaming_callback=None)
                result = await loop.run_in_executor(ex, run_chunked)
                text = (result or "").strip().replace("You are a helpful AI assistant named SmolLM, trained by Hugging Face", "")
                label = normalize_risk_label(text, fallback="Medium")
                label = combine_risk_labels(label, quantum_label)
                try:
                    await log_interaction("SECURITY_SCANNER_PROMPT:\n" + prompt, "SECURITY_SCANNER_RESULT:\n" + label, key)
                except Exception:
                    pass
                try:
                    del llm
                except Exception:
                    pass
                meta = {
                    "frame_changed": "YES" if frame_changed else "no",
                    "llm_detection": f"{llm_level} ({llm_score:.2f})",
                    "tamper_evidence": tamper_note or "none",
                    "color_shift": color_summary,
                    "quantum_color_risk": f"{quantum_label} ({quantum_score:.2f})",
                    "color_rag_context": color_rag_context,
                    "forecast_47h": forecast_47_summary,
                    "forecast_700h": forecast_700_summary,
                    "forecast_47h_series": forecast_47,
                    "forecast_700h_series": forecast_700,
                }
                try:
                    await append_security_event(
                        key,
                        kind="scan",
                        severity=label.lower(),
                        details=(
                            f"frame_changed={meta['frame_changed']} llm={meta['llm_detection']} "
                            f"tamper={meta['tamper_evidence']} color_shift={color_summary} "
                            f"quantum_color={meta['quantum_color_risk']}"
                        ),
                    )
                except Exception:
                    pass
                return label, text, meta
    except FileNotFoundError:
        return (
            "[Model not found]",
            "[Model not found. Place or download the GGUF model on device.]",
            {
                "frame_changed": "unknown",
                "llm_detection": "unknown",
                "tamper_evidence": "unknown",
                "color_shift": color_summary,
                "quantum_color_risk": f"{quantum_label} ({quantum_score:.2f})",
                "color_rag_context": color_rag_context,
                "forecast_47h": forecast_47_summary,
                "forecast_700h": forecast_700_summary,
                "forecast_47h_series": forecast_47,
                "forecast_700h_series": forecast_700,
            },
        )

class BackgroundGradient(Widget):
    top_color = ListProperty([0.07, 0.09, 0.14, 1])
    bottom_color = ListProperty([0.02, 0.03, 0.05, 1])
    steps = NumericProperty(44)
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
    radius = NumericProperty(dp(26))
    fill = ListProperty([1, 1, 1, 0.055])
    border = ListProperty([1, 1, 1, 0.13])
    highlight = ListProperty([1, 1, 1, 0.08])
    _shine_x = NumericProperty(0.0)
    _shine_alpha = NumericProperty(0.0)
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, radius=self._redraw, fill=self._redraw, border=self._redraw, highlight=self._redraw, _shine_x=self._redraw, _shine_alpha=self._redraw)
        Clock.schedule_once(lambda dt: self._start_shine(), 0.2)
    def _start_shine(self):
        self._shine_x = -0.3
        self._shine_alpha = 0.0
        anim = (Animation(_shine_alpha=0.22, duration=0.45, t="out_quad") & Animation(_shine_x=1.3, duration=1.1, t="out_cubic"))
        anim2 = Animation(_shine_alpha=0.0, duration=0.40, t="out_quad")
        loop = (anim + anim2)
        loop.repeat = True
        loop.start(self)
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
            if self._shine_alpha > 0.001:
                sx = x + w * self._shine_x
                Color(1, 1, 1, float(self._shine_alpha))
                Rectangle(pos=(sx, y), size=(w * 0.18, h))

class GradientButton(MDRaisedButton):
    start_color = ListProperty([0.16, 0.48, 0.96, 1])
    end_color = ListProperty([0.42, 0.25, 0.96, 1])
    steps = NumericProperty(24)
    radius = NumericProperty(dp(18))
    border_color = ListProperty([1, 1, 1, 0.18])
    border_width = NumericProperty(dp(1.0))
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.md_bg_color = (0, 0, 0, 0)
        self.elevation = 0
        self.bind(
            pos=self._redraw,
            size=self._redraw,
            start_color=self._redraw,
            end_color=self._redraw,
            steps=self._redraw,
            radius=self._redraw,
            border_color=self._redraw,
            border_width=self._redraw,
        )
        Clock.schedule_once(lambda dt: self._redraw(), 0)
    def _build_gradient_texture(self) -> Texture:
        steps = max(2, int(self.steps))
        buf = bytearray()
        for i in range(steps):
            t = i / (steps - 1)
            r = self.start_color[0] + (self.end_color[0] - self.start_color[0]) * t
            g = self.start_color[1] + (self.end_color[1] - self.start_color[1]) * t
            b = self.start_color[2] + (self.end_color[2] - self.start_color[2]) * t
            a = self.start_color[3] + (self.end_color[3] - self.start_color[3]) * t
            buf.extend([int(255 * r), int(255 * g), int(255 * b), int(255 * a)])
        texture = Texture.create(size=(1, steps), colorfmt="rgba")
        texture.blit_buffer(bytes(buf), colorfmt="rgba", bufferfmt="ubyte")
        texture.wrap = "repeat"
        texture.mag_filter = "linear"
        texture.min_filter = "linear"
        return texture
    def _redraw(self, *args):
        self.canvas.before.clear()
        x, y = self.pos
        w, h = self.size
        if w <= 0 or h <= 0:
            return
        texture = self._build_gradient_texture()
        with self.canvas.before:
            Color(1, 1, 1, 1)
            RoundedRectangle(pos=(x, y), size=(w, h), radius=[self.radius], texture=texture)
            Color(*self.border_color)
            Line(rounded_rectangle=[x, y, w, h, self.radius], width=self.border_width)

class ColorTab(Widget):
    rgb = ListProperty([0.2, 0.6, 0.9, 1.0])
    radius = NumericProperty(dp(12))
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, rgb=self._redraw, radius=self._redraw)
    def _redraw(self, *args):
        self.canvas.clear()
        x, y = self.pos
        w, h = self.size
        with self.canvas:
            Color(0, 0, 0, 0.3)
            RoundedRectangle(pos=(x, y - dp(1)), size=(w, h + dp(2)), radius=[self.radius])
            Color(*self.rgb)
            RoundedRectangle(pos=(x, y), size=(w, h), radius=[self.radius])

class RiskWheelNeo(Widget):
    value = NumericProperty(0.5)
    level = StringProperty("MEDIUM")
    sweep = NumericProperty(0.0)
    glow = NumericProperty(0.25)
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, value=self._redraw, sweep=self._redraw, glow=self._redraw, level=self._redraw)
        Clock.schedule_once(lambda dt: self._start_sweep(), 0.05)
    def _start_sweep(self):
        a = Animation(sweep=1.0, duration=2.2, t="linear")
        a.repeat = True
        a.start(self)
        anim = Animation(glow=0.42, duration=0.9, t="in_out_quad") + Animation(glow=0.22, duration=0.9, t="in_out_quad")
        anim.repeat = True
        anim.start(self)
    def set_level(self, level: str):
        lvl = (level or "").strip().upper()
        if lvl.startswith("LOW"):
            target = 0.0
            self.level = "LOW"
        elif lvl.startswith("HIGH"):
            target = 1.0
            self.level = "HIGH"
        else:
            target = 0.5
            self.level = "MEDIUM"
        Animation.cancel_all(self, "value")
        Animation(value=target, duration=0.55, t="out_cubic").start(self)
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
        sweep_ang = -135.0 + 270.0 * float(self.sweep)
        sweep_width = 18.0
        active_rgb = self._level_color()
        pulse = float(self.glow)
        segs = [
            ("LOW",  (0.10, 0.85, 0.40), -135.0, -45.0),
            ("MED",  (0.98, 0.78, 0.20),  -45.0,  45.0),
            ("HIGH", (0.98, 0.22, 0.30),   45.0, 135.0),
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
                active = (self.level == "LOW" and name == "LOW") or (self.level == "MEDIUM" and name == "MED") or (self.level == "HIGH" and name == "HIGH")
                boost = 1.0 + (0.85 * pulse if active else 0.0)
                for k in range(5, 0, -1):
                    alpha = (0.05 + 0.03 * k) * boost
                    Color(rgb[0], rgb[1], rgb[2], alpha)
                    Line(circle=(cx, cy, r, a0g, a1g), width=thickness + dp(2.6 * k), cap="round")
                Color(rgb[0], rgb[1], rgb[2], 0.78)
                Line(circle=(cx, cy, r, a0g, a1g), width=thickness, cap="round")
            Color(active_rgb[0], active_rgb[1], active_rgb[2], 0.22 + 0.18 * pulse)
            Line(circle=(cx, cy, r, sweep_ang - sweep_width/2.0, sweep_ang + sweep_width/2.0), width=thickness + dp(6), cap="round")
            Color(1, 1, 1, 0.12)
            Line(circle=(cx, cy, r, sweep_ang - sweep_width/5.0, sweep_ang + sweep_width/5.0), width=thickness - dp(2), cap="round")
            nx = cx + math.cos(ang_rad) * (r * 0.92)
            ny = cy + math.sin(ang_rad) * (r * 0.92)
            Color(active_rgb[0], active_rgb[1], active_rgb[2], 0.18 + 0.18 * pulse)
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
<ColorTab>:
    size_hint: None, None
<RiskWheelNeo>:
    size_hint: None, None
<GradientButton>:
    font_style: "Button"
    text_color: 0.98, 0.99, 1, 1

MDScreen:
    MDBoxLayout:
        orientation: "vertical"
        MDTopAppBar:
            title: "Secure LLM Security Scanner"
            elevation: 10
            md_bg_color: 0.04, 0.05, 0.08, 1
            specific_text_color: 0.96, 0.97, 0.99, 1
            title_align: "left"
            left_action_items: [["shield-check", lambda x: None]]
            right_action_items: [["bell-outline", lambda x: None], ["cog-outline", lambda x: None]]
        MDLabel:
            id: status_label
            text: ""
            color: 0.78, 0.82, 0.88, 1
            size_hint_y: None
            height: "24dp"
            halign: "center"
        MDScreenManager:
            id: screen_manager

            MDScreen:
                name: "chat"
                BackgroundGradient:
                    top_color: 0.06, 0.08, 0.13, 1
                    bottom_color: 0.02, 0.03, 0.05, 1
                MDBoxLayout:
                    orientation: "vertical"
                    padding: "10dp"
                    spacing: "10dp"
                    FloatLayout:
                        size_hint_y: 1
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
                            padding: "12dp"
                            spacing: "10dp"
                            pos: self.parent.pos
                            size: self.parent.size
                            ScrollView:
                                MDLabel:
                                    id: chat_history
                                    text: ""
                                    markup: True
                                    size_hint_y: None
                                    height: self.texture_size[1]
                            MDTextField:
                                id: chat_input
                                hint_text: "Type your message"
                                multiline: False
                                on_text_validate: app.on_chat_send()
                            GradientButton:
                                text: "Send"
                                size_hint_x: 1
                                start_color: 0.18, 0.5, 0.96, 1
                                end_color: 0.55, 0.3, 0.98, 1
                                on_release: app.on_chat_send()

            MDScreen:
                name: "scanner"
                BackgroundGradient:
                    top_color: 0.07, 0.09, 0.14, 1
                    bottom_color: 0.02, 0.03, 0.05, 1
                MDBoxLayout:
                    orientation: "vertical"
                    padding: "10dp"
                    spacing: "10dp"
                    FloatLayout:
                        size_hint_y: None
                        height: "650dp"
                        GlassCard:
                            pos: self.parent.pos
                            size: self.parent.size
                            height: self.parent.height
                            radius: dp(26)
                            fill: 1, 1, 1, 0.055
                            border: 1, 1, 1, 0.13
                            highlight: 1, 1, 1, 0.08
                        MDBoxLayout:
                            orientation: "vertical"
                            padding: "14dp"
                            spacing: "10dp"
                            pos: self.parent.pos
                            size: self.parent.size
                            MDLabel:
                                text: "Active Security Scanner"
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
                            MDBoxLayout:
                                size_hint_y: None
                                height: "26dp"
                                spacing: "8dp"
                                MDLabel:
                                    text: "Entropic Color Tab"
                                    theme_text_color: "Secondary"
                                    size_hint_x: 0.7
                                ColorTab:
                                    id: entropic_tab
                                    size: "70dp", "18dp"
                                    pos_hint: {"center_y": 0.5}
                            MDLabel:
                                id: risk_text
                                text: "RISK: —"
                                halign: "center"
                                size_hint_y: None
                                height: "22dp"
                            MDTextField:
                                id: site_field
                                hint_text: "Site (e.g., HQ East)"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDTextField:
                                id: zone_field
                                hint_text: "Zone (loading dock / lobby)"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDTextField:
                                id: human_field
                                hint_text: "Human activity (none / loitering / crowd)"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDTextField:
                                id: camera_field
                                hint_text: "Camera notes (angle / obstruction)"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDTextField:
                                id: access_field
                                hint_text: "Access control (locked / open / forced)"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDTextField:
                                id: frame_field
                                hint_text: "Frame signature / hash"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDTextField:
                                id: movement_alarm_field
                                hint_text: "Movement alarm colors (label:#RRGGBB; label:120,30,40)"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDTextField:
                                id: settle_field
                                hint_text: "Settle state colors (label:#RRGGBB; label:120,30,40)"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDTextField:
                                id: llm_field
                                hint_text: "LLM detection notes (if any)"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDTextField:
                                id: tamper_field
                                hint_text: "Tamper evidence"
                                mode: "fill"
                                fill_color: 1, 1, 1, 0.06
                            MDLabel:
                                id: alert_status
                                text: "Alerts: —"
                                theme_text_color: "Secondary"
                                size_hint_y: None
                                height: "20dp"
                            MDLabel:
                                id: color_change_status
                                text: "Color shift: —"
                                theme_text_color: "Secondary"
                                size_hint_y: None
                                height: "34dp"
                                halign: "center"
                            MDLabel:
                                id: forecast_status
                                text: "Forecast: —"
                                theme_text_color: "Secondary"
                                size_hint_y: None
                                height: "44dp"
                                halign: "center"
                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "44dp"
                                GradientButton:
                                    text: "Start 24/7 Capture"
                                    start_color: 0.14, 0.65, 0.42, 1
                                    end_color: 0.12, 0.45, 0.3, 1
                                    on_release: app.gui_start_capture()
                                GradientButton:
                                    text: "Stop Capture"
                                    start_color: 0.85, 0.25, 0.35, 1
                                    end_color: 0.65, 0.15, 0.25, 1
                                    on_release: app.gui_stop_capture()
                            MDLabel:
                                id: capture_status
                                text: "Capture: idle"
                                theme_text_color: "Secondary"
                                size_hint_y: None
                                height: "20dp"
                            GradientButton:
                                text: "Scan Security Risk"
                                size_hint_x: 1
                                start_color: 0.18, 0.5, 0.96, 1
                                end_color: 0.55, 0.3, 0.98, 1
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
                                type: "determinate"
                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "44dp"
                                GradientButton:
                                    text: "Download"
                                    start_color: 0.14, 0.65, 0.42, 1
                                    end_color: 0.12, 0.45, 0.3, 1
                                    on_release: app.gui_model_download()
                                GradientButton:
                                    text: "Verify SHA"
                                    start_color: 0.26, 0.33, 0.52, 1
                                    end_color: 0.18, 0.23, 0.36, 1
                                    on_release: app.gui_model_verify()
                                GradientButton:
                                    text: "Encrypt"
                                    start_color: 0.95, 0.62, 0.22, 1
                                    end_color: 0.85, 0.45, 0.15, 1
                                    on_release: app.gui_model_encrypt()
                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "44dp"
                                GradientButton:
                                    text: "Decrypt"
                                    start_color: 0.95, 0.62, 0.22, 1
                                    end_color: 0.85, 0.45, 0.15, 1
                                    on_release: app.gui_model_decrypt()
                                GradientButton:
                                    text: "Delete plain"
                                    start_color: 0.85, 0.25, 0.35, 1
                                    end_color: 0.65, 0.15, 0.25, 1
                                    on_release: app.gui_model_delete_plain()
                                GradientButton:
                                    text: "Refresh"
                                    start_color: 0.26, 0.33, 0.52, 1
                                    end_color: 0.18, 0.23, 0.36, 1
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
                                text: "Chat History"
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
                                    fill_color: 1, 1, 1, 0.06
                                GradientButton:
                                    text: "Search"
                                    start_color: 0.18, 0.5, 0.96, 1
                                    end_color: 0.55, 0.3, 0.98, 1
                                    on_release: app.gui_history_search()
                                GradientButton:
                                    text: "Clear"
                                    start_color: 0.85, 0.25, 0.35, 1
                                    end_color: 0.65, 0.15, 0.25, 1
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
                                GradientButton:
                                    text: "Prev"
                                    start_color: 0.26, 0.33, 0.52, 1
                                    end_color: 0.18, 0.23, 0.36, 1
                                    on_release: app.gui_history_prev()
                                GradientButton:
                                    text: "Next"
                                    start_color: 0.26, 0.33, 0.52, 1
                                    end_color: 0.18, 0.23, 0.36, 1
                                    on_release: app.gui_history_next()
                                GradientButton:
                                    text: "Refresh"
                                    start_color: 0.26, 0.33, 0.52, 1
                                    end_color: 0.18, 0.23, 0.36, 1
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
                                GradientButton:
                                    text: "New random key"
                                    start_color: 0.18, 0.5, 0.96, 1
                                    end_color: 0.55, 0.3, 0.98, 1
                                    on_release: app.gui_rekey_random()
                                GradientButton:
                                    text: "Passphrase key"
                                    start_color: 0.18, 0.5, 0.96, 1
                                    end_color: 0.55, 0.3, 0.98, 1
                                    on_release: app.gui_rekey_passphrase_dialog()
                            MDProgressBar:
                                id: rekey_progress
                                value: 0
                                max: 100
                                type: "determinate"
                            MDLabel:
                                id: rekey_status
                                text: "—"
                                theme_text_color: "Secondary"

            MDScreen:
                name: "playback"
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
                                text: "Playback (Heightened Events)"
                                bold: True
                                font_style: "H6"
                                size_hint_y: None
                                height: "32dp"
                            Video:
                                id: playback_video
                                state: "stop"
                                allow_stretch: True
                                keep_ratio: True
                            MDLabel:
                                id: playback_status
                                text: "Select a chunk to play."
                                theme_text_color: "Secondary"
                                size_hint_y: None
                                height: "20dp"
                            ScrollView:
                                MDList:
                                    id: playback_list
                            MDBoxLayout:
                                spacing: "8dp"
                                size_hint_y: None
                                height: "44dp"
                                GradientButton:
                                    text: "Refresh"
                                    start_color: 0.26, 0.33, 0.52, 1
                                    end_color: 0.18, 0.23, 0.36, 1
                                    on_release: app.gui_playback_refresh()
                                GradientButton:
                                    text: "Stop"
                                    start_color: 0.85, 0.25, 0.35, 1
                                    end_color: 0.65, 0.15, 0.25, 1
                                    on_release: app.gui_playback_stop()

        MDBottomNavigation:
            panel_color: 0.08,0.09,0.12,1
            MDBottomNavigationItem:
                name: "nav_chat"
                text: "Chat"
                icon: "chat"
                on_tab_press: app.switch_screen("chat")
            MDBottomNavigationItem:
                name: "nav_scanner"
                text: "Scanner"
                icon: "shield-search"
                on_tab_press: app.switch_screen("scanner")
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
                name: "nav_playback"
                text: "Playback"
                icon: "play-circle-outline"
                on_tab_press: app.switch_screen("playback")
"""

class SecureLLMApp(MDApp):
    chat_history_text = ""
    _hist_page = 0
    _hist_per_page = 10
    _hist_search = None
    _capture_running = False
    _capture_thread = None
    _playback_page = 0
    _playback_per_page = 20
    _playback_alert_only = True
    _playback_tmp = None
    def build(self):
        self.title = "Secure LLM Security Scanner"
        self.theme_cls.primary_palette = "Blue"
        self.last_forecast_47 = []
        self.last_forecast_700 = []
        root = Builder.load_string(KV)
        if request_permissions and Permission:
            request_permissions([Permission.CAMERA, Permission.RECORD_AUDIO, Permission.WRITE_EXTERNAL_STORAGE])
        Clock.schedule_once(lambda dt: self.gui_model_refresh(), 0.2)
        Clock.schedule_once(lambda dt: self.gui_history_refresh(), 0.3)
        Clock.schedule_once(lambda dt: self.gui_model_autoprepare(), 0.4)
        Clock.schedule_once(lambda dt: self.gui_playback_refresh(), 0.6)
        return root
    def switch_screen(self, name: str):
        self.root.ids.screen_manager.current = name
    def set_status(self, text: str):
        self.root.ids.status_label.text = text
    def _run_bg(self, work_fn, done_fn=None, err_fn=None):
        def runner():
            try:
                out = work_fn()
                if done_fn:
                    Clock.schedule_once(lambda dt: done_fn(out), 0)
            except Exception as e:
                if err_fn:
                    Clock.schedule_once(lambda dt: err_fn(e), 0)
                else:
                    Clock.schedule_once(lambda dt: self.set_status(f"[Error] {e}"), 0)
        threading.Thread(target=runner, daemon=True).start()
    def append_chat(self, who: str, msg: str):
        chat_screen = self.root.ids.screen_manager.get_screen("chat")
        label = chat_screen.ids.chat_history
        self.chat_history_text += f"[b]{who}>[/b] {msg}\n"
        label.text = self.chat_history_text
    def on_chat_send(self):
        chat_screen = self.root.ids.screen_manager.get_screen("chat")
        field = chat_screen.ids.chat_input
        prompt = field.text.strip()
        if not prompt:
            return
        field.text = ""
        self.append_chat("You", prompt)
        self.set_status("Thinking...")
        threading.Thread(target=self._chat_worker, args=(prompt,), daemon=True).start()
    def _chat_worker(self, prompt: str):
        try:
            result = asyncio.run(mobile_run_chat(prompt))
        except Exception as e:
            result = f"[Error: {e}]"
        Clock.schedule_once(lambda dt: self._chat_finish(result))
    def _chat_finish(self, reply: str):
        self.append_chat("Model", reply)
        self.set_status("")
    def on_scan(self):
        road_screen = self.root.ids.screen_manager.get_screen("scanner")
        data = {
            "site": road_screen.ids.site_field.text.strip() or "unspecified site",
            "zone": road_screen.ids.zone_field.text.strip() or "unknown",
            "human_activity": road_screen.ids.human_field.text.strip() or "unknown",
            "camera_notes": road_screen.ids.camera_field.text.strip() or "none",
            "access_control": road_screen.ids.access_field.text.strip() or "unknown",
            "frame_signature": road_screen.ids.frame_field.text.strip() or "none",
            "movement_alarm_colors": road_screen.ids.movement_alarm_field.text.strip() or "none",
            "settle_colors": road_screen.ids.settle_field.text.strip() or "none",
            "llm_detection": road_screen.ids.llm_field.text.strip() or "none",
            "tamper_evidence": road_screen.ids.tamper_field.text.strip() or "none",
        }
        self.set_status("Scanning security risk...")
        threading.Thread(target=self._scan_worker, args=(data,), daemon=True).start()
    def _scan_worker(self, data: dict):
        try:
            label, raw, meta = asyncio.run(mobile_run_security_scan(data))
        except Exception as e:
            label, raw, meta = "[Error]", f"[Error: {e}]", {"frame_changed": "unknown", "llm_detection": "unknown", "tamper_evidence": "unknown"}
        Clock.schedule_once(lambda dt: self._scan_finish(label, raw, meta))
    def _scan_finish(self, label: str, raw: str, meta: Dict[str, str]):
        road_screen = self.root.ids.screen_manager.get_screen("scanner")
        try:
            road_screen.ids.risk_wheel.set_level(label)
            road_screen.ids.risk_text.text = f"RISK: {label.upper()}"
        except Exception:
            pass
        road_screen.ids.scan_result.text = label
        try:
            road_screen.ids.alert_status.text = f"Alerts: frame_change={meta.get('frame_changed')} llm={meta.get('llm_detection')} tamper={meta.get('tamper_evidence')}"
        except Exception:
            pass
        try:
            road_screen.ids.color_change_status.text = f"Color shift: {meta.get('color_shift', 'none')} | Quantum risk: {meta.get('quantum_color_risk', 'unknown')}"
        except Exception:
            pass
        try:
            road_screen.ids.forecast_status.text = f"{meta.get('forecast_47h', '47h forecast unavailable')} | {meta.get('forecast_700h', '700h forecast unavailable')}"
        except Exception:
            pass
        self.last_forecast_47 = meta.get("forecast_47h_series", [])
        self.last_forecast_700 = meta.get("forecast_700h_series", [])
        try:
            metrics = collect_system_metrics()
            rgb = metrics_to_rgb(metrics)
            road_screen.ids.entropic_tab.rgb = [rgb[0], rgb[1], rgb[2], 1.0]
        except Exception:
            pass
        self.set_status("")
    def gui_start_capture(self):
        if self._capture_running:
            return
        self._capture_running = True
        self.root.ids.capture_status.text = "Capture: starting..."
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()
    def gui_stop_capture(self):
        if not self._capture_running:
            return
        self._capture_running = False
        self.root.ids.capture_status.text = "Capture: stopping..."
    def _capture_loop(self):
        if not is_android():
            Clock.schedule_once(lambda dt: setattr(self.root.ids.capture_status, "text", "Capture: Android only"), 0)
            self._capture_running = False
            return
        recorder = AndroidRecorder()
        while self._capture_running:
            try:
                tmp_path = _tmp_path("capture_chunk", ".mp4")
                recorder.start(str(tmp_path))
                start_time = time.time()
                while self._capture_running and (time.time() - start_time) < CHUNK_SECONDS:
                    time.sleep(0.5)
                out_path = recorder.stop()
                if not out_path:
                    continue
                chunk_path = self._finalize_chunk(Path(out_path))
                Clock.schedule_once(lambda dt, p=chunk_path: setattr(self.root.ids.capture_status, "text", f"Capture: saved {p.name}"), 0)
            except Exception as e:
                Clock.schedule_once(lambda dt: setattr(self.root.ids.capture_status, "text", f"Capture error: {e}"), 0)
                time.sleep(1.0)
        Clock.schedule_once(lambda dt: setattr(self.root.ids.capture_status, "text", "Capture: idle"), 0)
    def _finalize_chunk(self, tmp_path: Path) -> Path:
        key = get_or_create_key()
        ts = time.strftime("%Y%m%d_%H%M%S")
        final_name = f"chunk_{ts}.mp4.aes"
        final_path = CHUNKS_DIR / final_name
        signature = compute_chunk_signature(tmp_path)
        loop_detected = False
        repeat_count = 0
        try:
            prior_sig = asyncio.run(fetch_security_state(key, "last_chunk_sig")) or ""
            prior_count = asyncio.run(fetch_security_state(key, "last_chunk_repeat")) or "0"
            repeat_count = int(prior_count)
            if prior_sig == signature:
                repeat_count += 1
            else:
                repeat_count = 0
            loop_detected = repeat_count >= 3
            asyncio.run(upsert_security_state(key, "last_chunk_sig", signature))
            asyncio.run(upsert_security_state(key, "last_chunk_repeat", str(repeat_count)))
        except Exception:
            pass
        try:
            encrypt_file(tmp_path, final_path, key)
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            asyncio.run(append_media_chunk(key, str(final_path), CHUNK_SECONDS, signature, loop_detected))
        except Exception:
            pass
        if loop_detected:
            try:
                asyncio.run(
                    append_security_event(
                        key,
                        kind="loop_detected",
                        severity="high",
                        details=f"chunk_signature={signature[:12]} repeats={repeat_count}",
                    )
                )
            except Exception:
                pass
        self._cleanup_old_chunks()
        return final_path
    def _cleanup_old_chunks(self):
        try:
            chunks = sorted(CHUNKS_DIR.glob("chunk_*.mp4.aes"), key=lambda p: p.stat().st_mtime, reverse=True)
            for extra in chunks[CHUNK_KEEP_LIMIT:]:
                extra.unlink(missing_ok=True)
        except Exception:
            pass
    def gui_model_refresh(self):
        s = []
        s.append(f"Encrypted: {'YES' if ENCRYPTED_MODEL.exists() else 'no'}")
        s.append(f"Plain: {'YES' if MODEL_PATH.exists() else 'no'}")
        s.append(f"Key: {'YES' if KEY_PATH.exists() else 'no'}")
        if MODEL_PATH.exists():
            s.append(f"PlainMB: {MODEL_PATH.stat().st_size/1024/1024:.1f}")
        if ENCRYPTED_MODEL.exists():
            s.append(f"EncMB: {ENCRYPTED_MODEL.stat().st_size/1024/1024:.1f}")
        self.root.ids.model_status.text = " | ".join(s)
        self.root.ids.model_progress.value = 0
    def gui_model_autoprepare(self):
        if ENCRYPTED_MODEL.exists():
            return
        self.set_status("Auto-preparing model...")
        self.root.ids.model_progress.value = 0
        url = MODEL_REPO + MODEL_FILE
        def work():
            key = get_or_create_key()
            if MODEL_PATH.exists():
                with _MODEL_LOCK:
                    encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, key)
                    MODEL_PATH.unlink(missing_ok=True)
                return "Encrypted existing model."
            def cb(done, total):
                if total > 0:
                    pct = int(done * 100 / total)
                    Clock.schedule_once(lambda dt: setattr(self.root.ids.model_progress, "value", pct), 0)
            sha = download_model_httpx_with_cb(url, MODEL_PATH, progress_cb=cb, timeout=None)
            with _MODEL_LOCK:
                encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, key)
                MODEL_PATH.unlink(missing_ok=True)
            return f"Downloaded+encrypted (SHA={sha[:12]}...)"
        def done(msg):
            self.set_status("")
            self.gui_model_refresh()
            self.root.ids.model_status.text = f"Auto model ready: {msg}"
        def err(e):
            self.set_status("")
            self.root.ids.model_status.text = f"Auto model failed: {e}"
        self._run_bg(work, done, err)
    def gui_model_download(self):
        self.set_status("Downloading...")
        self.root.ids.model_progress.value = 0
        url = MODEL_REPO + MODEL_FILE
        def work():
            key = get_or_create_key()
            def cb(done, total):
                if total > 0:
                    pct = int(done * 100 / total)
                    Clock.schedule_once(lambda dt: setattr(self.root.ids.model_progress, "value", pct), 0)
            sha = download_model_httpx_with_cb(url, MODEL_PATH, progress_cb=cb, timeout=None)
            with _MODEL_LOCK:
                encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, key)
                MODEL_PATH.unlink(missing_ok=True)
            return sha
        def done(sha):
            self.set_status("")
            self.gui_model_refresh()
            ok = (sha.lower() == EXPECTED_HASH.lower())
            self.root.ids.model_status.text = f"Downloaded+encrypted SHA={sha} | expected={EXPECTED_HASH} | match={'YES' if ok else 'NO'}"
        def err(e):
            self.set_status("")
            self.root.ids.model_status.text = f"Download failed: {e}"
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
        self._run_bg(work, done)
    def gui_model_encrypt(self):
        if not MODEL_PATH.exists():
            self.root.ids.model_status.text = "No plaintext model."
            return
        self.set_status("Encrypting...")
        def work():
            key = get_or_create_key()
            with _MODEL_LOCK:
                encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, key)
            return True
        def done(_):
            self.set_status("")
            self.gui_model_refresh()
            self.root.ids.model_status.text = "Encrypted model created."
        def err(e):
            self.set_status("")
            self.root.ids.model_status.text = f"Encrypt failed: {e}"
        self._run_bg(work, done, err)
    def gui_model_decrypt(self):
        if not ENCRYPTED_MODEL.exists():
            self.root.ids.model_status.text = "No encrypted model."
            return
        self.set_status("Decrypting...")
        def work():
            key = get_or_create_key()
            with _MODEL_LOCK:
                decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, key)
            return True
        def done(_):
            self.set_status("")
            self.gui_model_refresh()
            self.root.ids.model_status.text = "Plaintext model present."
        def err(e):
            self.set_status("")
            self.root.ids.model_status.text = f"Decrypt failed: {e}"
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
            except Exception as e:
                self.root.ids.model_status.text = f"Delete failed: {e}"
    def gui_history_refresh(self):
        self.set_status("Loading history...")
        self.root.ids.history_list.clear_widgets()
        page = self._hist_page
        per_page = self._hist_per_page
        search = self._hist_search
        def work():
            key = get_or_create_key()
            asyncio.run(ensure_db_schema(key))
            rows = asyncio.run(fetch_history(key, limit=per_page, offset=page * per_page, search=search))
            return rows
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
        self._run_bg(work, done, err)
    def _history_show_dialog(self, rid, ts, prompt, resp):
        body = f"[{rid}] {ts}\n\nQ:\n{prompt}\n\nA:\n{resp}"
        dlg = MDDialog(title="History Entry", text=body, buttons=[MDFlatButton(text="Close", on_release=lambda x: dlg.dismiss())])
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
    def gui_playback_refresh(self):
        self.set_status("Loading playback...")
        self.root.ids.playback_list.clear_widgets()
        page = self._playback_page
        per_page = self._playback_per_page
        alert_only = self._playback_alert_only
        def work():
            key = get_or_create_key()
            asyncio.run(ensure_db_schema(key))
            rows = asyncio.run(fetch_media_chunks(key, alert_only=alert_only, limit=per_page, offset=page * per_page))
            return rows
        def done(rows):
            self.set_status("")
            if not rows:
                self.root.ids.playback_list.add_widget(TwoLineListItem(text="No chunks", secondary_text="—"))
                return
            for (rid, ts, path, duration, signature, alert) in rows:
                label = f"[{rid}] {ts} ({duration}s)"
                secondary = f"alert={'YES' if alert else 'no'} sig={signature[:10]}"
                self.root.ids.playback_list.add_widget(
                    TwoLineListItem(
                        text=label,
                        secondary_text=secondary,
                        on_release=lambda item, p=path: self.gui_playback_select(p),
                    )
                )
        def err(e):
            self.set_status("")
            self.root.ids.playback_status.text = f"Playback error: {e}"
        self._run_bg(work, done, err)
    def gui_playback_select(self, path: str):
        key = get_or_create_key()
        enc_path = Path(path)
        if not enc_path.exists():
            self.root.ids.playback_status.text = "Chunk missing."
            return
        tmp_plain = _tmp_path("playback", ".mp4")
        try:
            decrypt_file(enc_path, tmp_plain, key)
        except Exception as e:
            self.root.ids.playback_status.text = f"Decrypt failed: {e}"
            return
        if self._playback_tmp:
            try:
                Path(self._playback_tmp).unlink(missing_ok=True)
            except Exception:
                pass
        self._playback_tmp = str(tmp_plain)
        self.root.ids.playback_video.source = self._playback_tmp
        self.root.ids.playback_video.state = "play"
        self.root.ids.playback_status.text = f"Playing {enc_path.name}"
    def gui_playback_stop(self):
        try:
            self.root.ids.playback_video.state = "stop"
        except Exception:
            pass
        self.root.ids.playback_status.text = "Stopped."
    def _gui_rekey_common(self, make_new_key_fn: Callable[[], bytes]):
        self.set_status("Rekeying...")
        self.root.ids.rekey_progress.value = 5
        self.root.ids.rekey_status.text = "Decrypting..."
        def work():
            with _MODEL_LOCK, _CRYPTO_LOCK:
                old_key = get_or_create_key()
                tmp_model = _tmp_path("model_rekey", ".gguf")
                tmp_db = _tmp_path("db_rekey", ".db")
                wrote_model = False
                wrote_db = False
                try:
                    if ENCRYPTED_MODEL.exists():
                        decrypt_file(ENCRYPTED_MODEL, tmp_model, old_key)
                    if DB_PATH.exists():
                        decrypt_file(DB_PATH, tmp_db, old_key)
                    new_key = make_new_key_fn()
                    Clock.schedule_once(lambda dt: setattr(self.root.ids.rekey_progress, "value", 55), 0)
                    if tmp_model.exists():
                        enc = aes_encrypt(tmp_model.read_bytes(), new_key)
                        _atomic_write_bytes(ENCRYPTED_MODEL, enc)
                        wrote_model = True
                    Clock.schedule_once(lambda dt: setattr(self.root.ids.rekey_progress, "value", 80), 0)
                    if tmp_db.exists():
                        encdb = aes_encrypt(tmp_db.read_bytes(), new_key)
                        _atomic_write_bytes(DB_PATH, encdb)
                        wrote_db = True
                    return True
                finally:
                    try:
                        tmp_model.unlink(missing_ok=True)
                    except Exception:
                        pass
                    try:
                        tmp_db.unlink(missing_ok=True)
                    except Exception:
                        pass
        def done(_):
            self.set_status("")
            self.root.ids.rekey_progress.value = 100
            self.root.ids.rekey_status.text = "Rekey complete."
            self.gui_model_refresh()
        def err(e):
            self.set_status("")
            self.root.ids.rekey_progress.value = 0
            self.root.ids.rekey_status.text = f"Rekey failed: {e}"
        self._run_bg(work, done, err)
    def gui_rekey_random(self):
        def make_new_key():
            new_key = AESGCM.generate_key(256)
            _atomic_write_bytes(KEY_PATH, new_key)
            return new_key
        self._gui_rekey_common(make_new_key)
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
            return
        dlg.dismiss()
        pw = pw1.strip()
        def make_new_key():
            salt, derived = derive_key_from_passphrase(pw)
            _atomic_write_bytes(KEY_PATH, salt + derived)
            return derived
        self._gui_rekey_common(make_new_key)

if __name__ == "__main__":
    SecureLLMApp().run()
