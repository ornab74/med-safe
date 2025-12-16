
import os
import re
import uuid
import math
import time
import hashlib
import threading
import logging
import gc
import random

from pathlib import Path
from typing import Optional, Tuple, Dict, List, Callable
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
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem
from kivymd.uix.screen import MDScreen
from kivymd.uix.textfield import MDTextField
from kivymd.uix.boxlayout import MDBoxLayout

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

try:
    import psutil
except Exception:
    psutil = None

try:
    import pennylane as qml
    import pennylane.numpy as pnp
except Exception:
    qml = None
    pnp = None

if _kivy_platform != "android" and hasattr(Window, "size"):
    Window.size = (420, 800)

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

CHUNK = 1024 * 1024

PKG_DIR = Path(__file__).resolve().parent
MODELS_SHIPPED = PKG_DIR / "models"

BASE_DIR: Optional[Path] = None
TMP_DIR: Optional[Path] = None
INSTALL_MASTER_PATH: Optional[Path] = None
INSTALL_MDK_WRAP_PATH: Optional[Path] = None
FIRST_BOOT_FLAG_PATH: Optional[Path] = None
LOG_PATH: Optional[Path] = None

logger = logging.getLogger("qroadscan")
logger.setLevel(logging.INFO)

class _FileHandler(logging.Handler):
    def __init__(self, get_log_path: Callable[[], Optional[Path]]):
        super().__init__()
        self._fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        self._get_log_path = get_log_path

    def emit(self, record):
        try:
            msg = self._fmt.format(record)
        except Exception:
            msg = str(record.getMessage())
        try:
            lp = self._get_log_path()
            if lp is not None:
                lp.parent.mkdir(parents=True, exist_ok=True)
                with lp.open("a", encoding="utf-8") as f:
                    f.write(msg + "\n")
        except Exception:
            pass
        try:
            app = MDApp.get_running_app()
            if app:
                app._debug_dirty = True
        except Exception:
            pass

def _get_log_path() -> Optional[Path]:
    return LOG_PATH

if not any(isinstance(h, _FileHandler) for h in logger.handlers):
    logger.addHandler(_FileHandler(_get_log_path))

def _read_log_tail(max_chars: int = 140_000) -> str:
    try:
        if LOG_PATH is None or not LOG_PATH.exists():
            return "—"
        t = LOG_PATH.read_text(encoding="utf-8", errors="ignore")
        return t[-max_chars:] if len(t) > max_chars else t
    except Exception:
        return "—"

def _pick_model_files():
    if not MODELS_SHIPPED.exists():
        return None, None, None
    aes_candidates = sorted(MODELS_SHIPPED.glob("*.gguf.aes")) + sorted(MODELS_SHIPPED.glob("*.aes"))
    for enc_path in aes_candidates:
        base_name = enc_path.name[:-4]
        wrap_path = MODELS_SHIPPED / (base_name + ".mdk.wrap")
        sha_path = MODELS_SHIPPED / (base_name + ".sha256")
        if wrap_path.exists():
            return enc_path, wrap_path, sha_path
    return (aes_candidates[0], None, None) if aes_candidates else (None, None, None)

MODEL_ENC_PATH, MODEL_BOOT_WRAP_PATH, MODEL_SHA_PATH = _pick_model_files()

def _require_paths():
    if BASE_DIR is None or TMP_DIR is None or INSTALL_MASTER_PATH is None or INSTALL_MDK_WRAP_PATH is None or FIRST_BOOT_FLAG_PATH is None or LOG_PATH is None:
        raise RuntimeError("paths not initialized")

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

def decrypt_file_gcm(src: Path, dst: Path, key32: bytes):
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

def _get_bootstrap_secret() -> bytes:
    try:
        import bootstrap_secret  # type: ignore
        b64 = getattr(bootstrap_secret, "BOOTSTRAP_SECRET_B64", "")
        if isinstance(b64, str) and b64.strip():
            import base64
            return base64.urlsafe_b64decode(b64 + "==")
    except Exception:
        pass
    s = os.environ.get("ANDROID_BOOTSTRAP_SECRET", "")
    if s:
        return s.encode("utf-8")
    return b"CHANGE_ME_USE_BUILD_TIME_INJECTION"

def bootstrap_key() -> bytes:
    return hkdf32(_get_bootstrap_secret(), b"qroadscan/bootstrap/v1")

def _load_install_master() -> Optional[bytes]:
    _require_paths()
    try:
        if not INSTALL_MASTER_PATH.exists():
            return None
        b = INSTALL_MASTER_PATH.read_bytes()
        return b[:32] if len(b) >= 32 else None
    except Exception:
        return None

def _save_install_master(k: bytes):
    _require_paths()
    _atomic_write(INSTALL_MASTER_PATH, k)

def _unwrap_mdk() -> bytes:
    _require_paths()
    master = _load_install_master()
    if master and INSTALL_MDK_WRAP_PATH.exists():
        try:
            blob = INSTALL_MDK_WRAP_PATH.read_bytes()
            mdk = decrypt_bytes_gcm(blob, master)
            if len(mdk) != 32:
                raise RuntimeError("bad mdk length")
            return mdk
        except Exception:
            try:
                INSTALL_MDK_WRAP_PATH.unlink(missing_ok=True)
            except Exception:
                pass
            try:
                INSTALL_MASTER_PATH.unlink(missing_ok=True)
            except Exception:
                pass
    if MODEL_BOOT_WRAP_PATH is None or not MODEL_BOOT_WRAP_PATH.exists():
        raise RuntimeError("Missing shipped .mdk.wrap (bootstrap)")
    blob = MODEL_BOOT_WRAP_PATH.read_bytes()
    try:
        mdk = decrypt_bytes_gcm(blob, bootstrap_key())
    except InvalidTag as e:
        raise RuntimeError("bootstrap unwrap failed (wrong bootstrap secret)") from e
    if len(mdk) != 32:
        raise RuntimeError("bad mdk length")
    new_master = os.urandom(32)
    _save_install_master(new_master)
    install_wrap = encrypt_bytes_gcm(mdk, new_master)
    _atomic_write(INSTALL_MDK_WRAP_PATH, install_wrap)
    logger.info("first-boot key rotation complete (install wrap created)")
    return mdk

def _tmp_plain_model_path() -> Path:
    _require_paths()
    return TMP_DIR / f"model_plain.{uuid.uuid4().hex}.gguf"

@contextmanager
def acquire_plain_model() -> Path:
    _require_paths()
    if MODEL_ENC_PATH is None or not MODEL_ENC_PATH.exists():
        raise FileNotFoundError("Missing shipped encrypted model (.aes) in ./models")
    mdk = _unwrap_mdk()
    plain = _tmp_plain_model_path()
    decrypt_file_gcm(MODEL_ENC_PATH, plain, mdk)
    try:
        if MODEL_SHA_PATH is not None and MODEL_SHA_PATH.exists():
            expected = (MODEL_SHA_PATH.read_text(encoding="utf-8", errors="ignore") or "").strip().split()[0]
            if expected and re.fullmatch(r"[0-9a-fA-F]{64}", expected):
                actual = sha256_file(plain)
                if actual.lower() != expected.lower():
                    raise RuntimeError(f"model sha mismatch: {actual} != {expected}")
    except Exception:
        try:
            plain.unlink(missing_ok=True)
        except Exception:
            pass
        raise
    try:
        yield plain
    finally:
        try:
            plain.unlink(missing_ok=True)
        except Exception:
            pass

def load_llama(model_path: Path):
    from llama_cpp import Llama
    try:
        c = os.cpu_count() or 1
    except Exception:
        c = 1
    threads = 2 if c >= 2 else 1
    return Llama(
        model_path=str(model_path),
        n_ctx=512,
        n_threads=threads,
        n_batch=64,
        use_mmap=False,
        use_mlock=False,
        n_gpu_layers=0,
        verbose=False,
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
    return (float(max(0.0, min(1.0, r))), float(max(0.0, min(1.0, g))), float(max(0.0, min(1.0, b))))

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

def punkd_analyze(prompt_text: str, top_n: int = 12) -> Dict[str, float]:
    toks = _simple_tokenize(prompt_text)
    freq: Dict[str, float] = {}
    for t in toks:
        freq[t] = freq.get(t, 0.0) + 1.0
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
        m = re.search(r"\b(Low|Medium|High)\b", assembled, re.IGNORECASE)
        if m:
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

def _heuristic_fallback(data: dict) -> str:
    txt = " ".join([str(v or "") for v in data.values()]).lower()
    if any(w in txt for w in ["ice", "snow", "fog", "flood", "whiteout", "hail", "blizzard"]):
        return "High"
    if "high" in txt and "traffic" in txt:
        return "High"
    if any(w in txt for w in ["construction", "debris", "pedestrian", "animal", "accident"]):
        return "High"
    if any(w in txt for w in ["rain", "wet"]) or any(w in txt for w in ["medium", "med"]):
        return "Medium"
    return "Low"

def run_scan_blocking(data: dict) -> Tuple[str, str]:
    prompt = build_road_scanner_prompt(data, include_system_entropy=True)
    out_text = ""
    with acquire_plain_model() as mp:
        llm = load_llama(mp)
        try:
            out_text = chunked_generate(
                llm,
                prompt,
                max_total_tokens=96,
                chunk_tokens=24,
                base_temperature=0.18,
                punkd_profile="balanced",
                streaming_callback=None,
            )
        finally:
            try:
                llm.close()
            except Exception:
                pass
            try:
                del llm
            except Exception:
                pass
            try:
                gc.collect()
            except Exception:
                pass
            time.sleep(0.03)
    m = re.search(r"\b(low|medium|high)\b", out_text, re.IGNORECASE)
    label = m.group(1).capitalize() if m else ""
    if label not in ("Low", "Medium", "High"):
        label = _heuristic_fallback(data)
    return label, out_text

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
            title: "Road Safe"
            elevation: 8
            right_action_items: [["information-outline", lambda x: app.switch_screen("about")], ["shield-lock-outline", lambda x: app.switch_screen("privacy")]]

        ScreenManager:
            id: screen_manager
            size_hint_y: 1

            MDScreen:
                name: "road"
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
                            height: card_body.minimum_height + dp(34)

                            GlassCard:
                                pos: self.pos
                                size: self.size
                                radius: dp(28)

                            MDBoxLayout:
                                id: card_body
                                orientation: "vertical"
                                size_hint: 1, None
                                height: self.minimum_height
                                pos: self.parent.pos
                                padding: "18dp"
                                spacing: "14dp"

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "34dp"
                                    spacing: "10dp"

                                    MDLabel:
                                        text: "Road Risk Scanner"
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

                                MDTextField:
                                    id: loc_field
                                    hint_text: "Location"
                                    mode: "fill"
                                    helper_text_mode: "on_focus"
                                    helper_text: "Only input needed"
                                    size_hint_x: 1

                                MDRaisedButton:
                                    id: scan_btn
                                    text: "Scan Risk"
                                    size_hint_x: 1
                                    on_release: app.on_scan()

                                MDLabel:
                                    id: scan_result
                                    text: ""
                                    halign: "center"
                                    size_hint_y: None
                                    height: "22dp"
                                    theme_text_color: "Secondary"

                        FloatLayout:
                            size_hint_y: None
                            height: helper_body.minimum_height + dp(32)

                            GlassCard:
                                pos: self.pos
                                size: self.size
                                radius: dp(28)
                                fill: 1, 1, 1, 0.045
                                border: 1, 1, 1, 0.11
                                highlight: 1, 1, 1, 0.07

                            MDBoxLayout:
                                id: helper_body
                                orientation: "vertical"
                                size_hint: 1, None
                                height: self.minimum_height
                                pos: self.parent.pos
                                padding: "16dp"
                                spacing: "10dp"

                                MDLabel:
                                    text: "What this does"
                                    font_style: "Subtitle1"
                                    bold: True
                                    halign: "left"
                                    theme_text_color: "Custom"
                                    text_color: 0.90, 0.92, 0.96, 0.95
                                    size_hint_y: None
                                    height: "22dp"

                                MDLabel:
                                    text: "Runs an on-device model and returns a simple risk label. No accounts. No sign-in. No cloud calls."
                                    halign: "left"
                                    theme_text_color: "Secondary"
                                    size_hint_y: None
                                    height: self.texture_size[1] + dp(6)
                                    text_size: self.width, None

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "40dp"
                                    spacing: "10dp"

                                    MDFlatButton:
                                        text: "How it works"
                                        on_release: app.switch_screen("about")

                                    MDFlatButton:
                                        text: "Privacy policy"
                                        on_release: app.switch_screen("privacy")

            MDScreen:
                name: "about"
                BackgroundGradient:
                    top_color: 0.07, 0.09, 0.14, 1
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
                            height: about_body.minimum_height + dp(34)

                            GlassCard:
                                pos: self.pos
                                size: self.size
                                radius: dp(28)

                            MDBoxLayout:
                                id: about_body
                                orientation: "vertical"
                                size_hint: 1, None
                                height: self.minimum_height
                                pos: self.parent.pos
                                padding: "18dp"
                                spacing: "12dp"

                                MDLabel:
                                    text: "Welcome to Road Safe"
                                    font_style: "H5"
                                    bold: True
                                    halign: "left"
                                    theme_text_color: "Custom"
                                    text_color: 0.92, 0.94, 0.98, 0.96
                                    size_hint_y: None
                                    height: self.texture_size[1] + dp(2)
                                    text_size: self.width, None

                                MDLabel:
                                    markup: True
                                    text:
                                        "[b]What you see[/b]\n"
                                        "• A single input: [b]Location[/b]\n"
                                        "• A dial that reports: [b]Low / Medium / High[/b]\n"
                                        "• A neutral state before any scan is run\n"
                                        "\n"
                                        "[b]What happens when you scan[/b]\n"
                                        "1) The app prepares an encrypted on-device model.\n"
                                        "2) It runs a short inference and extracts one of the allowed labels.\n"
                                        "3) If the output is malformed, a conservative heuristic chooses a label.\n"
                                        "\n"
                                        "[b]First-boot security (advanced)[/b]\n"
                                        "• The shipped model is stored encrypted.\n"
                                        "• On first boot, the app unwraps a model key using a bootstrap secret and immediately rotates to an install-specific key stored in private app storage.\n"
                                        "• A temporary plaintext model file may be created during a scan and is deleted when scanning completes.\n"
                                        "\n"
                                        "[b]Operational behavior[/b]\n"
                                        "• This app is designed to run offline.\n"
                                        "• Results are an advisory risk label, not a guarantee.\n"
                                        "• If you need safety-critical guidance, rely on official road/weather sources.\n"
                                    halign: "left"
                                    theme_text_color: "Secondary"
                                    text_size: self.width, None
                                    size_hint_y: None
                                    height: self.texture_size[1] + dp(8)

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "44dp"
                                    spacing: "10dp"

                                    MDRaisedButton:
                                        text: "Continue to Scanner"
                                        size_hint_x: 1
                                        on_release: app.accept_about()

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "40dp"
                                    spacing: "10dp"

                                    MDFlatButton:
                                        text: "Read Privacy Policy"
                                        on_release: app.switch_screen("privacy")

                                    Widget:

                                    MDFlatButton:
                                        text: "Go to Scan"
                                        on_release: app.switch_screen("road")

            MDScreen:
                name: "privacy"
                BackgroundGradient:
                    top_color: 0.06, 0.08, 0.13, 1
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
                            height: privacy_body.minimum_height + dp(34)

                            GlassCard:
                                pos: self.pos
                                size: self.size
                                radius: dp(28)
                                fill: 1, 1, 1, 0.055
                                border: 1, 1, 1, 0.14
                                highlight: 1, 1, 1, 0.09

                            MDBoxLayout:
                                id: privacy_body
                                orientation: "vertical"
                                size_hint: 1, None
                                height: self.minimum_height
                                pos: self.parent.pos
                                padding: "18dp"
                                spacing: "12dp"

                                MDLabel:
                                    text: "Privacy Policy"
                                    font_style: "H5"
                                    bold: True
                                    halign: "left"
                                    theme_text_color: "Custom"
                                    text_color: 0.92, 0.94, 0.98, 0.96
                                    size_hint_y: None
                                    height: self.texture_size[1] + dp(2)
                                    text_size: self.width, None

                                MDLabel:
                                    markup: True
                                    text:
                                        "[b]Summary[/b]\n"
                                        "Road Safe is built for offline use. It does not require an account and is designed to avoid transmitting your data.\n"
                                        "\n"
                                        "[b]Data you provide[/b]\n"
                                        "• Location text you type into the app (free-form).\n"
                                        "• Optional diagnostic actions you trigger (e.g., opening the Debug tab).\n"
                                        "\n"
                                        "[b]Data processing[/b]\n"
                                        "• Your input is used to build a prompt and run a local model inference.\n"
                                        "• The app shows only a risk label (Low/Medium/High) plus UI state.\n"
                                        "\n"
                                        "[b]Network / sharing[/b]\n"
                                        "• The app does not intentionally upload your location or scan results.\n"
                                        "• No analytics SDK is required for the core scanner flow.\n"
                                        "\n"
                                        "[b]Local storage[/b]\n"
                                        "The app may store:\n"
                                        "• Encrypted key material used to unwrap the model key after first boot (private app storage).\n"
                                        "• A debug log file that records technical events and errors (private app storage).\n"
                                        "• Temporary model artifacts during a scan. These are deleted when the scan ends.\n"
                                        "\n"
                                        "[b]Debug log[/b]\n"
                                        "• The log may contain device/platform information, file paths within private storage, and error traces.\n"
                                        "• Avoid entering sensitive personal data into the Location field if you plan to export/share logs.\n"
                                        "\n"
                                        "[b]Your choices[/b]\n"
                                        "• You can clear the debug log inside the Debug page.\n"
                                        "• You control what you type into Location.\n"
                                        "\n"
                                        "[b]Safety note[/b]\n"
                                        "Risk labels are informational. Always prioritize official road conditions and your direct observations.\n"
                                    halign: "left"
                                    theme_text_color: "Secondary"
                                    text_size: self.width, None
                                    size_hint_y: None
                                    height: self.texture_size[1] + dp(8)

                                MDBoxLayout:
                                    size_hint_y: None
                                    height: "44dp"
                                    spacing: "10dp"

                                    MDRaisedButton:
                                        text: "Back to Scan"
                                        size_hint_x: 1
                                        on_release: app.switch_screen("road")

                        FloatLayout:
                            size_hint_y: None
                            height: privacy_footer.minimum_height + dp(28)

                            GlassCard:
                                pos: self.pos
                                size: self.size
                                radius: dp(28)
                                fill: 1, 1, 1, 0.04
                                border: 1, 1, 1, 0.10
                                highlight: 1, 1, 1, 0.06

                            MDBoxLayout:
                                id: privacy_footer
                                orientation: "vertical"
                                size_hint: 1, None
                                height: self.minimum_height
                                pos: self.parent.pos
                                padding: "16dp"
                                spacing: "10dp"

                                MDLabel:
                                    text: "Local files"
                                    bold: True
                                    font_style: "Subtitle1"
                                    halign: "left"
                                    theme_text_color: "Custom"
                                    text_color: 0.90, 0.92, 0.96, 0.95
                                    size_hint_y: None
                                    height: "22dp"

                                MDLabel:
                                    text: "Base directory: " + app.base_dir_str
                                    halign: "left"
                                    theme_text_color: "Secondary"
                                    size_hint_y: None
                                    height: self.texture_size[1] + dp(6)
                                    text_size: self.width, None

            MDScreen:
                name: "debug"
                BackgroundGradient:
                    top_color: 0.06, 0.08, 0.13, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                MDBoxLayout:
                    orientation: "vertical"
                    padding: "12dp"
                    spacing: "10dp"

                    MDBoxLayout:
                        size_hint_y: None
                        height: "44dp"
                        spacing: "8dp"

                        MDLabel:
                            id: debug_meta
                            text: "—"
                            theme_text_color: "Secondary"
                            halign: "left"

                        Widget:

                        MDIconButton:
                            icon: "delete-outline"
                            on_release: app.gui_debug_clear()

                        MDIconButton:
                            icon: "refresh"
                            on_release: app.gui_debug_refresh()

                    ScrollView:
                        MDLabel:
                            id: debug_text
                            text: ""
                            markup: False
                            size_hint_y: None
                            text_size: self.width, None
                            height: self.texture_size[1] + dp(12)

        MDBottomNavigation:
            id: bottom_nav
            size_hint_y: None
            height: "72dp"

            MDBottomNavigationItem:
                name: "nav_scan"
                text: "Scan"
                icon: "radar"
                on_tab_press: app.switch_screen("road")

            MDBottomNavigationItem:
                name: "nav_about"
                text: "About"
                icon: "information-outline"
                on_tab_press: app.switch_screen("about")

            MDBottomNavigationItem:
                name: "nav_privacy"
                text: "Privacy"
                icon: "shield-lock-outline"
                on_tab_press: app.switch_screen("privacy")

            MDBottomNavigationItem:
                name: "nav_debug"
                text: "Debug"
                icon: "bug-outline"
                on_tab_press: app.switch_screen("debug")
"""

KV = KV_TEMPLATE.replace("APPBAR_WIDGET", _APPBAR_NAME)

def _is_first_boot() -> bool:
    _require_paths()
    try:
        return not FIRST_BOOT_FLAG_PATH.exists()
    except Exception:
        return True

def _mark_first_boot_done():
    _require_paths()
    try:
        _atomic_write(FIRST_BOOT_FLAG_PATH, b"1")
    except Exception:
        pass

class SecureLLMApp(MDApp):
    _debug_dirty = False
    safe_top = NumericProperty(0)
    _scan_lock = threading.Lock()
    _scan_inflight = False
    base_dir_str = StringProperty("")
    _exec: Optional[ThreadPoolExecutor] = None

    def _init_paths(self):
        global BASE_DIR, TMP_DIR, INSTALL_MASTER_PATH, INSTALL_MDK_WRAP_PATH, FIRST_BOOT_FLAG_PATH, LOG_PATH
        ud = Path(self.user_data_dir)
        BASE_DIR = ud / "qroadscan_data"
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        TMP_DIR = BASE_DIR / "tmp"
        TMP_DIR.mkdir(parents=True, exist_ok=True)
        INSTALL_MASTER_PATH = BASE_DIR / ".install_master_key"
        INSTALL_MDK_WRAP_PATH = BASE_DIR / ".mdk.wrap.install"
        FIRST_BOOT_FLAG_PATH = BASE_DIR / ".first_boot_done"
        LOG_PATH = BASE_DIR / "debug.log"
        self.base_dir_str = str(BASE_DIR)

    def _cleanup_tmp(self):
        try:
            _require_paths()
            if TMP_DIR is None or not TMP_DIR.exists():
                return
            for p in TMP_DIR.glob("model_plain.*.gguf"):
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
        except Exception:
            pass

    def build(self):
        self.title = "Road Safe"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Blue"
        self.safe_top = dp(24) if _kivy_platform == "android" else 0
        self._init_paths()
        self._cleanup_tmp()
        self._exec = ThreadPoolExecutor(max_workers=1)
        return Builder.load_string(KV)

    def on_start(self):
        logger.info("app start platform=%s base=%s", _kivy_platform, str(BASE_DIR) if BASE_DIR else "—")
        logger.info("pkg=%s shipped_models=%s", str(PKG_DIR), str(MODELS_SHIPPED))
        logger.info("model_enc=%s boot_wrap=%s sha=%s", str(MODEL_ENC_PATH), str(MODEL_BOOT_WRAP_PATH), str(MODEL_SHA_PATH))
        try:
            import llama_cpp  # noqa
            logger.info("LLAMA: module import OK")
        except Exception as e:
            logger.exception("LLAMA: module import FAILED: %s", e)
        Clock.schedule_once(lambda dt: self.reset_ui(), 0.0)
        Clock.schedule_once(lambda dt: self.gui_debug_refresh(), 0.2)
        Clock.schedule_interval(self._debug_auto_refresh, 0.6)
        Clock.schedule_once(lambda dt: self._route_first_boot(), 0.0)

    def on_stop(self):
        try:
            if self._exec:
                self._exec.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    def _route_first_boot(self):
        try:
            if _is_first_boot():
                self.switch_screen("about")
            else:
                self.switch_screen("road")
        except Exception:
            self.switch_screen("road")

    def accept_about(self):
        _mark_first_boot_done()
        self.switch_screen("road")

    def _debug_auto_refresh(self, *args):
        try:
            if self.root.ids.screen_manager.current == "debug" or self._debug_dirty:
                self._debug_dirty = False
                self.gui_debug_refresh()
        except Exception:
            pass

    def switch_screen(self, name: str):
        try:
            self.root.ids.screen_manager.current = name
        except Exception:
            pass
        if name == "debug":
            self.gui_debug_refresh()

    def _pill(self, tone: str, text: str):
        try:
            road = self.root.ids.screen_manager.get_screen("road")
            road.ids.status_pill.tone = tone
            road.ids.status_pill_text.text = text
        except Exception:
            pass

    def reset_ui(self):
        try:
            road = self.root.ids.screen_manager.get_screen("road")
            road.ids.risk_wheel.set_level("Neutral", animate=False)
            road.ids.risk_text.text = "RISK: —"
            road.ids.scan_result.text = ""
            road.ids.scan_btn.disabled = False
            road.ids.scan_btn.text = "Scan Risk"
            self._pill("neutral", "Neutral")
        except Exception:
            pass
        self._scan_inflight = False

    def on_scan(self):
        if self._scan_inflight or self._exec is None:
            return
        with self._scan_lock:
            if self._scan_inflight:
                return
            self._scan_inflight = True
        road = self.root.ids.screen_manager.get_screen("road")
        try:
            road.ids.scan_btn.disabled = True
            road.ids.scan_btn.text = "Scanning..."
            road.ids.scan_result.text = ""
            road.ids.risk_text.text = "RISK: —"
            road.ids.risk_wheel.set_level("Neutral", animate=True)
            self._pill("warn", "Running")
        except Exception:
            pass
        data = {
            "location": (road.ids.loc_field.text or "").strip() or "unspecified location",
            "road_type": "unknown",
            "weather": "unknown",
            "traffic": "unknown",
            "obstacles": "none",
            "sensor_notes": "none",
        }
        scan_id = uuid.uuid4().hex[:10]
        logger.info("SCAN_UI: clicked id=%s", scan_id)
        fut = self._exec.submit(run_scan_blocking, data)
        fut.add_done_callback(lambda f: self._scan_done_callback(f, scan_id))

    def _scan_done_callback(self, fut, scan_id: str):
        try:
            label, raw = fut.result()
        except Exception as e:
            logger.exception("SCAN: failed id=%s", scan_id)
            label, raw = "", f"[Error] {e}"
        Clock.schedule_once(lambda dt: self._scan_finish(label, raw, scan_id), 0)

    def _scan_finish(self, label: str, raw: str, scan_id: str):
        road = self.root.ids.screen_manager.get_screen("road")
        lvl = (label or "").strip().capitalize()
        if lvl not in ("Low", "Medium", "High"):
            lvl = "Neutral"
        try:
            road.ids.risk_wheel.set_level(lvl, animate=True)
            road.ids.risk_text.text = "RISK: —" if lvl == "Neutral" else f"RISK: {lvl.upper()}"
            road.ids.scan_result.text = "" if lvl == "Neutral" else lvl
            if lvl == "Low":
                self._pill("good", "Low")
            elif lvl == "Medium":
                self._pill("warn", "Medium")
            elif lvl == "High":
                self._pill("bad", "High")
            else:
                self._pill("neutral", "Neutral")
        except Exception:
            pass
        try:
            road.ids.scan_btn.disabled = False
            road.ids.scan_btn.text = "Scan Risk"
        except Exception:
            pass
        self._scan_inflight = False
        logger.info("SCAN_UI: done id=%s label=%s raw=%s", scan_id, lvl, (raw or "")[:220].replace("\n", " "))

    def gui_debug_refresh(self):
        try:
            meta = f"file={'YES' if (LOG_PATH and LOG_PATH.exists()) else 'no'} | path={str(LOG_PATH) if LOG_PATH else '—'}"
            self.root.ids.debug_meta.text = meta
            self.root.ids.debug_text.text = _read_log_tail()
        except Exception:
            pass

    def gui_debug_clear(self):
        try:
            if LOG_PATH and LOG_PATH.exists():
                LOG_PATH.unlink()
        except Exception:
            pass
        self.gui_debug_refresh()

if __name__ == "__main__":
    SecureLLMApp().run()
```0
