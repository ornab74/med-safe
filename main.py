
import os
import re
import time
import uuid
import math
import hashlib
import threading
import logging

from pathlib import Path
from typing import Optional, Tuple
from contextlib import contextmanager

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
from kivy.properties import NumericProperty, StringProperty, ListProperty
from kivy.utils import platform as _kivy_platform

from kivymd.app import MDApp
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.toolbar import MDTopAppBar
from kivymd.uix.label import MDLabel
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem
from kivymd.uix.screen import MDScreen

try:
    from jnius import autoclass
except Exception:
    autoclass = None

# Desktop preview only
if _kivy_platform != "android" and hasattr(Window, "size"):
    Window.size = (420, 760)

CHUNK = 1024 * 1024
BOTTOM_NAV_H = 72  # dp

# ---------------------------
# Storage (internal app storage)
# ---------------------------

def _android_files_dir() -> Optional[Path]:
    if _kivy_platform != "android" or autoclass is None:
        return None
    try:
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        ctx = PythonActivity.mActivity
        return Path(str(ctx.getFilesDir().getAbsolutePath()))
    except Exception:
        return None

def _app_base_dir() -> Path:
    if _kivy_platform == "android":
        internal = _android_files_dir()
        if internal:
            d = internal / "qroadscan_data"
            d.mkdir(parents=True, exist_ok=True)
            return d
    d = Path.cwd() / "qroadscan_data"
    d.mkdir(parents=True, exist_ok=True)
    return d

BASE_DIR = _app_base_dir()
TMP_DIR = BASE_DIR / "tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)

# Shipped artifacts live in app package directory (read-only)
PKG_DIR = Path(__file__).resolve().parent
MODELS_SHIPPED = PKG_DIR / "models"

def _pick_model_files():
    """
    Find first encrypted model (*.aes) under shipped models folder and infer wrap+sha names.
    Works with names like:
      llama3-small-Q3_K_M.gguf.aes
      llama3-small-Q3_K_M.gguf.mdk.wrap
      llama3-small-Q3_K_M.gguf.sha256
    """
    if not MODELS_SHIPPED.exists():
        return None, None, None

    # Prefer *.gguf.aes first, fallback to any *.aes
    aes_candidates = sorted(MODELS_SHIPPED.glob("*.gguf.aes")) + sorted(MODELS_SHIPPED.glob("*.aes"))
    for enc_path in aes_candidates:
        base_name = enc_path.name[:-4]  # remove ".aes"
        wrap_path = MODELS_SHIPPED / (base_name + ".mdk.wrap")
        sha_path = MODELS_SHIPPED / (base_name + ".sha256")
        if wrap_path.exists():
            return enc_path, wrap_path, sha_path
    return (aes_candidates[0], None, None) if aes_candidates else (None, None, None)

MODEL_ENC_PATH, MODEL_BOOT_WRAP_PATH, MODEL_SHA_PATH = _pick_model_files()

# First-boot persistent state (internal private storage)
INSTALL_MASTER_PATH = BASE_DIR / ".install_master_key"      # 32 bytes master
INSTALL_MDK_WRAP_PATH = BASE_DIR / ".mdk.wrap.install"      # MDK wrapped with install master

# ---------------------------
# Logging
# ---------------------------

LOG_PATH = BASE_DIR / "debug.log"
logger = logging.getLogger("qroadscan")
logger.setLevel(logging.INFO)

class _FileHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self._fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    def emit(self, record):
        try:
            msg = self._fmt.format(record)
        except Exception:
            msg = str(record.getMessage())
        try:
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with LOG_PATH.open("a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass
        try:
            app = MDApp.get_running_app()
            if app:
                app._debug_dirty = True
        except Exception:
            pass

if not any(isinstance(h, _FileHandler) for h in logger.handlers):
    logger.addHandler(_FileHandler())

def _read_log_tail(max_chars: int = 120_000) -> str:
    try:
        if not LOG_PATH.exists():
            return "—"
        t = LOG_PATH.read_text(encoding="utf-8", errors="ignore")
        return t[-max_chars:] if len(t) > max_chars else t
    except Exception:
        return "—"

# ---------------------------
# Crypto helpers (AES-GCM)
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

# ---------------------------
# Bootstrap secret (build-time injection recommended)
# ---------------------------
# Best: have CI write a python file `bootstrap_secret.py` with BOOTSTRAP_SECRET_B64.
# Example contents:
#   BOOTSTRAP_SECRET_B64 = "...."
#
# This is NOT the model key; it only unwraps the MDK once at first boot.
#
def _get_bootstrap_secret() -> bytes:
    # 1) build-time injected python module (recommended)
    try:
        import bootstrap_secret  # type: ignore
        b64 = getattr(bootstrap_secret, "BOOTSTRAP_SECRET_B64", "")
        if isinstance(b64, str) and b64.strip():
            import base64
            return base64.urlsafe_b64decode(b64 + "==")
    except Exception:
        pass

    # 2) debug/testing env var
    s = os.environ.get("ANDROID_BOOTSTRAP_SECRET", "")
    if s:
        return s.encode("utf-8")

    # 3) fallback (functional but NOT secure)
    return b"CHANGE_ME_USE_BUILD_TIME_INJECTION"

def bootstrap_key() -> bytes:
    return hkdf32(_get_bootstrap_secret(), b"qroadscan/bootstrap/v1")

# ---------------------------
# Key rotation + envelope
# ---------------------------

def _load_install_master() -> Optional[bytes]:
    try:
        if not INSTALL_MASTER_PATH.exists():
            return None
        b = INSTALL_MASTER_PATH.read_bytes()
        return b[:32] if len(b) >= 32 else None
    except Exception:
        return None

def _save_install_master(k: bytes):
    _atomic_write(INSTALL_MASTER_PATH, k)

def _unwrap_mdk() -> bytes:
    """
    Returns MDK (32 bytes).
    - Preferred: unwrap install wrap with install master
    - Else: unwrap shipped bootstrap wrap with bootstrap_key(), then rotate:
        create install master + store install wrap in private storage
    """
    # Use install wrap if present
    master = _load_install_master()
    if master and INSTALL_MDK_WRAP_PATH.exists():
        blob = INSTALL_MDK_WRAP_PATH.read_bytes()
        mdk = decrypt_bytes_gcm(blob, master)
        if len(mdk) != 32:
            raise RuntimeError("bad mdk length")
        return mdk

    # First boot: unwrap with bootstrap key
    if MODEL_BOOT_WRAP_PATH is None or not MODEL_BOOT_WRAP_PATH.exists():
        raise RuntimeError("Missing shipped .mdk.wrap (bootstrap)")
    blob = MODEL_BOOT_WRAP_PATH.read_bytes()
    try:
        mdk = decrypt_bytes_gcm(blob, bootstrap_key())
    except InvalidTag as e:
        raise RuntimeError("bootstrap unwrap failed (wrong bootstrap secret)") from e

    if len(mdk) != 32:
        raise RuntimeError("bad mdk length")

    # Rotate: new install master, wrap MDK into internal storage
    new_master = os.urandom(32)
    _save_install_master(new_master)
    install_wrap = encrypt_bytes_gcm(mdk, new_master)
    _atomic_write(INSTALL_MDK_WRAP_PATH, install_wrap)
    logger.info("first-boot key rotation complete (install wrap created)")
    return mdk

def _tmp_plain_model_path() -> Path:
    return TMP_DIR / f"model_plain.{uuid.uuid4().hex}.gguf"

@contextmanager
def acquire_plain_model() -> Path:
    if MODEL_ENC_PATH is None or not MODEL_ENC_PATH.exists():
        raise FileNotFoundError("Missing shipped encrypted model (.aes) in ./models")

    logger.info("MODEL: encrypted=%s", str(MODEL_ENC_PATH))
    mdk = _unwrap_mdk()

    plain = _tmp_plain_model_path()
    logger.info("MODEL: decrypt -> %s", str(plain))
    decrypt_file_gcm(MODEL_ENC_PATH, plain, mdk)

    # Optional offline integrity check (plaintext)
    try:
        if MODEL_SHA_PATH is not None and MODEL_SHA_PATH.exists():
            expected = (MODEL_SHA_PATH.read_text(encoding="utf-8", errors="ignore") or "").strip().split()[0]
            if expected and re.fullmatch(r"[0-9a-fA-F]{64}", expected):
                actual = sha256_file(plain)
                if actual.lower() != expected.lower():
                    raise RuntimeError(f"model sha mismatch: {actual} != {expected}")
                logger.info("MODEL: sha256 OK")
    except Exception as e:
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

# ---------------------------
# Llama inference (Android-safe)
# ---------------------------

def load_llama(model_path: Path):
    """
    On Android, `use_mmap=True` frequently causes native crashes.
    These settings are conservative and stable.
    """
    logger.info("LLAMA: import llama_cpp")
    from llama_cpp import Llama

    threads = 2
    try:
        # keep conservative; too many threads can crash on some devices
        threads = 2 if (os.cpu_count() or 1) >= 2 else 1
    except Exception:
        threads = 2

    logger.info("LLAMA: init (use_mmap=False, n_ctx=512, n_batch=64, threads=%d)", threads)
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

def build_prompt(data: dict) -> str:
    return (
        "You are a road risk classifier.\n"
        "Reply with ONLY one word: Low, Medium, or High.\n"
        "Choose Low when conditions are normal/clear and traffic is low.\n"
        "Choose High when visibility is poor, surface is hazardous, traffic is heavy, or obstacles exist.\n\n"
        f"Location: {data.get('location','unspecified')}\n"
        f"Road type: {data.get('road_type','unknown')}\n"
        f"Weather: {data.get('weather','unknown')}\n"
        f"Traffic: {data.get('traffic','unknown')}\n"
        f"Obstacles: {data.get('obstacles','none')}\n"
        f"Notes: {data.get('sensor_notes','none')}\n"
    )

def run_scan_blocking(data: dict) -> Tuple[str, str]:
    prompt = build_prompt(data)
    logger.info("SCAN: start")

    with acquire_plain_model() as mp:
        logger.info("SCAN: model ready size_mb=%.1f", mp.stat().st_size / 1024 / 1024)

        llm = load_llama(mp)

        logger.info("SCAN: inference call")
        out = llm(prompt, max_tokens=16, temperature=0.2)

        text = ""
        if isinstance(out, dict):
            try:
                text = out.get("choices", [{"text": ""}])[0].get("text", "")
            except Exception:
                text = ""
        else:
            text = str(out)

        text = (text or "").strip()

    m = re.search(r"\b(low|medium|high)\b", text, re.IGNORECASE)
    label = m.group(1).capitalize() if m else ""
    if label not in ("Low", "Medium", "High"):
        label = _heuristic_fallback(data)

    logger.info("SCAN: done label=%s raw=%s", label, text[:120].replace("\n", " "))
    return label, text

# ---------------------------
# UI Widgets
# ---------------------------

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
        if lvl == "LOW":
            self.level = "LOW"; self.value = 0.0
        elif lvl == "HIGH":
            self.level = "HIGH"; self.value = 1.0
        else:
            self.level = "MEDIUM"; self.value = 0.5

    def _level_color(self):
        if self.level == "LOW": return (0.10, 0.90, 0.42)
        if self.level == "HIGH": return (0.98, 0.22, 0.30)
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
            ((0.10, 0.85, 0.40), -135.0, -45.0),
            ((0.98, 0.78, 0.20), -45.0, 45.0),
            ((0.98, 0.22, 0.30), 45.0, 135.0),
        ]
        gap = 6.0

        with self.canvas:
            Color(1, 1, 1, 0.05)
            Line(circle=(cx, cy, r + dp(10), -140, 140), width=dp(1.2))
            Color(0.10, 0.12, 0.18, 0.65)
            Line(circle=(cx, cy, r, -140, 140), width=thickness, cap="round")

            for rgb, a0, a1 in segs:
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

<RiskWheelNeo>:
    size_hint: None, None

MDScreen:
    MDBoxLayout:
        id: root_box
        orientation: "vertical"
        padding: 0, app.safe_top, 0, 0
        spacing: "6dp"

        MDTopAppBar:
            title: "Road Safe"
            elevation: 8

        MDLabel:
            id: status_label
            text: ""
            size_hint_y: None
            height: "20dp"
            halign: "center"
            theme_text_color: "Secondary"

        ScreenManager:
            id: screen_manager
            size_hint_y: 1

            MDScreen:
                name: "road"
                BackgroundGradient:
                    top_color: 0.07, 0.09, 0.14, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                ScrollView:
                    do_scroll_x: False

                    MDBoxLayout:
                        orientation: "vertical"
                        padding: "12dp"
                        spacing: "12dp"
                        adaptive_height: True

                        FloatLayout:
                            size_hint_y: None
                            height: content.minimum_height + dp(28)

                            GlassCard:
                                pos: self.pos
                                size: self.size
                                radius: dp(26)
                                fill: 1, 1, 1, 0.055
                                border: 1, 1, 1, 0.13
                                highlight: 1, 1, 1, 0.08

                            MDBoxLayout:
                                id: content
                                orientation: "vertical"
                                size_hint: 1, None
                                height: self.minimum_height
                                pos: self.parent.pos
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
                                    height: "220dp"
                                    padding: "6dp"
                                    RiskWheelNeo:
                                        id: risk_wheel
                                        size: "210dp", "210dp"
                                        pos_hint: {"center_x": 0.5, "center_y": 0.52}

                                MDLabel:
                                    id: risk_text
                                    text: "RISK: —"
                                    halign: "center"
                                    size_hint_y: None
                                    height: "22dp"

                                MDTextField:
                                    id: loc_field
                                    hint_text: "Location"
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
                name: "debug"
                BackgroundGradient:
                    top_color: 0.06, 0.08, 0.13, 1
                    bottom_color: 0.02, 0.03, 0.05, 1

                MDBoxLayout:
                    orientation: "vertical"
                    padding: "12dp"
                    spacing: "10dp"

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

                    ScrollView:
                        MDLabel:
                            id: debug_text
                            text: ""
                            markup: False
                            size_hint_y: None
                            text_size: self.width, None
                            height: self.texture_size[1] + dp(10)

        MDBottomNavigation:
            id: bottom_nav
            size_hint_y: None
            height: "72dp"

            MDBottomNavigationItem:
                name: "nav_road"
                text: "Road"
                icon: "road-variant"
                on_tab_press: app.switch_screen("road")

            MDBottomNavigationItem:
                name: "nav_debug"
                text: "Debug"
                icon: "bug-outline"
                on_tab_press: app.switch_screen("debug")
"""

class SecureLLMApp(MDApp):
    _debug_dirty = False
    safe_top = NumericProperty(0)

    def build(self):
        self.title = "Road Safe"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Blue"

        # Simple status-bar offset for Android (prevents title being covered)
        self.safe_top = dp(24) if _kivy_platform == "android" else 0

        root = Builder.load_string(KV)
        return root

    def on_start(self):
        logger.info("app start platform=%s base=%s", _kivy_platform, str(BASE_DIR))
        logger.info("pkg=%s shipped_models=%s", str(PKG_DIR), str(MODELS_SHIPPED))
        logger.info("model_enc=%s boot_wrap=%s sha=%s",
                    str(MODEL_ENC_PATH), str(MODEL_BOOT_WRAP_PATH), str(MODEL_SHA_PATH))

        # Import llama_cpp on main thread once (often reduces native weirdness)
        try:
            import llama_cpp  # noqa
            logger.info("LLAMA: module import OK")
        except Exception as e:
            logger.exception("LLAMA: module import FAILED: %s", e)

        Clock.schedule_once(lambda dt: self.gui_debug_refresh(), 0.2)
        Clock.schedule_interval(lambda dt: self._debug_auto_refresh(), 0.6)

        # Default screen
        try:
            self.root.ids.screen_manager.current = "road"
        except Exception:
            pass

    def _debug_auto_refresh(self):
        try:
            if self.root.ids.screen_manager.current == "debug" or self._debug_dirty:
                self._debug_dirty = False
                self.gui_debug_refresh()
        except Exception:
            pass

    def set_status(self, text: str):
        try:
            self.root.ids.status_label.text = text
        except Exception:
            pass

    def switch_screen(self, name: str):
        try:
            self.root.ids.screen_manager.current = name
        except Exception:
            pass
        if name == "debug":
            self.gui_debug_refresh()

    def on_scan(self):
        road_screen = self.root.ids.screen_manager.get_screen("road")
        data = {
            "location": road_screen.ids.loc_field.text.strip() or "unspecified",
            "road_type": road_screen.ids.road_type_field.text.strip() or "unknown",
            "weather": road_screen.ids.weather_field.text.strip() or "unknown",
            "traffic": road_screen.ids.traffic_field.text.strip() or "unknown",
            "obstacles": road_screen.ids.obstacles_field.text.strip() or "none",
            "sensor_notes": road_screen.ids.sensor_notes_field.text.strip() or "none",
        }
        scan_id = uuid.uuid4().hex[:10]
        self.set_status("Scanning...")
        logger.info("SCAN_UI: clicked id=%s", scan_id)
        threading.Thread(target=self._scan_worker, args=(data, scan_id), daemon=True).start()

    def _scan_worker(self, data: dict, scan_id: str):
        try:
            label, raw = run_scan_blocking(data)
        except Exception as e:
            logger.exception("SCAN: failed id=%s", scan_id)
            label, raw = "Medium", f"[Error] {e}"
        Clock.schedule_once(lambda dt: self._scan_finish(label, raw, scan_id), 0)

    def _scan_finish(self, label: str, raw: str, scan_id: str):
        road_screen = self.root.ids.screen_manager.get_screen("road")
        if label not in ("Low", "Medium", "High"):
            label = "Medium"
        try:
            road_screen.ids.risk_wheel.set_level(label)
            road_screen.ids.risk_text.text = f"RISK: {label.upper()}"
            road_screen.ids.scan_result.text = label
        except Exception:
            pass
        self.set_status("")
        logger.info("SCAN_UI: done id=%s label=%s raw=%s", scan_id, label, (raw or "")[:140].replace("\n", " "))

    def gui_debug_refresh(self):
        try:
            meta = f"file={'YES' if LOG_PATH.exists() else 'no'} | path={str(LOG_PATH)}"
            self.root.ids.debug_meta.text = meta
            self.root.ids.debug_text.text = _read_log_tail()
        except Exception:
            pass

    def gui_debug_clear(self):
        try:
            if LOG_PATH.exists():
                LOG_PATH.unlink()
        except Exception:
            pass
        self.gui_debug_refresh()

if __name__ == "__main__":
    SecureLLMApp().run()
