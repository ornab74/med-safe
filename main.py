# main.py
# Medicine Reminder (KivyMD) — Advanced UI + Encrypted DB + Android AlarmManager (persistent)
#
# Single-file project:
# - Run normally:            python main.py
# - Generate Android Java + manifest injection files for Buildozer:
#                            python main.py --gen-android
#
# Buildozer notes (in buildozer.spec):
#   requirements = python3,kivy,kivymd,pyjnius,cryptography
#   android.api = 34
#   android.minapi = 24
#   android.permissions = POST_NOTIFICATIONS,SCHEDULE_EXACT_ALARM,RECEIVE_BOOT_COMPLETED,WAKE_LOCK,VIBRATE
#   android.add_src = android_src
#   android.extra_manifest_xml = android_src/extra_manifest.xml
#
# IMPORTANT:
# - Set PACKAGE_DOMAIN / PACKAGE_NAME to match your buildozer.spec (package.domain / package.name).

import os, sys, time, json, uuid, logging, sqlite3, threading, hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from contextlib import contextmanager
from threading import RLock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from kivy.lang import Builder
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.uix.widget import Widget
from kivy.animation import Animation
from kivy.metrics import dp
from kivy.graphics import Color, Line, RoundedRectangle, Rectangle, Ellipse
from kivy.properties import NumericProperty, ListProperty, StringProperty
from kivy.utils import platform as _kivy_platform

from kivymd.app import MDApp
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDFlatButton, MDRaisedButton, MDIconButton
from kivymd.uix.list import TwoLineIconListItem, OneLineIconListItem, IconLeftWidget, MDList
from kivymd.uix.textfield import MDTextField
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.picker import MDTimePicker

try:
    from jnius import autoclass, cast
except Exception:
    autoclass = None
    cast = None

# -------------------------
# Package identity (for Java)
# -------------------------
PACKAGE_DOMAIN = "org.example"
PACKAGE_NAME = "medreminder"
JAVA_PACKAGE = f"{PACKAGE_DOMAIN}.{PACKAGE_NAME}"  # org.example.medreminder
JAVA_ALARM_RECEIVER = f"{JAVA_PACKAGE}.AlarmReceiver"
JAVA_BOOT_RECEIVER = f"{JAVA_PACKAGE}.BootReceiver"

if _kivy_platform != "android" and hasattr(Window, "size"):
    Window.size = (420, 760)

# -------------------------
# Paths / Locks
# -------------------------
_CRYPTO_LOCK = RLock()
_SCHEDULE_LOCK = RLock()
_LOG_LOCK = RLock()

def _is_writable_dir(p: Path) -> bool:
    try:
        p.mkdir(parents=True, exist_ok=True)
        t = p / f".writetest.{uuid.uuid4().hex}"
        t.write_text("ok", encoding="utf-8")
        t.unlink(missing_ok=True)
        return True
    except Exception:
        return False

def _android_files_dir() -> Optional[Path]:
    if _kivy_platform != "android" or autoclass is None:
        return None
    try:
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        activity = PythonActivity.mActivity
        d = activity.getFilesDir().getAbsolutePath()
        return Path(str(d))
    except Exception:
        return None

def _app_base_dir() -> Path:
    p = os.environ.get("ANDROID_PRIVATE")
    if p:
        d = Path(p) / "medreminder_data"
        if _is_writable_dir(d):
            return d

    af = _android_files_dir()
    if af:
        d = af / "medreminder_data"
        if _is_writable_dir(d):
            return d

    d = Path(__file__).resolve().parent / "medreminder_data"
    d.mkdir(parents=True, exist_ok=True)
    return d

BASE_DIR = _app_base_dir()
DB_PATH = BASE_DIR / "medicines.db.aes"
KEY_PATH = BASE_DIR / ".enc_key"
LOG_PATH = BASE_DIR / "app.log"
TMP_DIR = BASE_DIR / "tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)

# -------------------------
# Logging ring buffer
# -------------------------
class _RingLog:
    def __init__(self, max_lines=800):
        self.max_lines = int(max_lines)
        self._lines = []
        self._lock = RLock()

    def add(self, line: str):
        line = (line or "").rstrip("\n")
        if not line:
            return
        with self._lock:
            self._lines.append(line)
            if len(self._lines) > self.max_lines:
                self._lines = self._lines[-self.max_lines:]

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

logger = logging.getLogger("medreminder")
logger.setLevel(logging.INFO)
if not any(isinstance(h, _FileAndRingHandler) for h in logger.handlers):
    logger.addHandler(_FileAndRingHandler())

# -------------------------
# Crypto utilities
# -------------------------
def _atomic_write_bytes(path: Path, data: bytes):
    tmp = path.with_suffix(path.suffix + f".tmp.{uuid.uuid4().hex}")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_bytes(data)
    tmp.replace(path)

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

# -------------------------
# Android Keystore (optional) - wraps AES key with RSA keypair stored in AndroidKeyStore
# -------------------------
_ANDROID_KEY_ALIAS = "medreminder_key_v1"

def _android_ready() -> bool:
    return _kivy_platform == "android" and autoclass is not None

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
    Builder = autoclass("android.security.keystore.KeyGenParameterSpec$Builder")

    purposes = int(KeyProperties.PURPOSE_ENCRYPT) | int(KeyProperties.PURPOSE_DECRYPT)
    builder = Builder(alias, purposes)
    builder.setDigests([KeyProperties.DIGEST_SHA256])
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
        logger.info("key stored: android keystore")
    else:
        _atomic_write_bytes(KEY_PATH, raw_key)
        logger.info("key stored: file")

def _load_wrapped_key() -> Optional[bytes]:
    if not KEY_PATH.exists():
        return None
    d = KEY_PATH.read_bytes()
    if _android_ready():
        try:
            k = _android_keystore_unwrap_key(d)
            if len(k) == 32:
                return k
        except Exception:
            logger.exception("key unwrap failed; falling back")
            return None
    return d[:32] if len(d) >= 32 else None

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
        return key

def _tmp_path(prefix: str, suffix: str) -> Path:
    return TMP_DIR / f"{prefix}.{uuid.uuid4().hex}{suffix}"

# -------------------------
# Encrypted SQLite DB
# -------------------------
class MedicineDB:
    def __init__(self, key: bytes):
        self.key = key
        self._ensure_db()

    def _ensure_db(self):
        with _CRYPTO_LOCK:
            if DB_PATH.exists():
                return
            tmp = _tmp_path("init", ".db")
            try:
                conn = sqlite3.connect(str(tmp))
                c = conn.cursor()
                c.execute("""
                    CREATE TABLE medicines (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        dosage TEXT,
                        frequency TEXT,
                        times TEXT,          -- JSON list of "HH:MM"
                        start_date TEXT,
                        end_date TEXT,
                        notes TEXT,
                        active INTEGER DEFAULT 1
                    )
                """)
                c.execute("""
                    CREATE TABLE dosage_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        medicine_id INTEGER,
                        scheduled_time TEXT,
                        taken_time TEXT,
                        status TEXT,
                        FOREIGN KEY(medicine_id) REFERENCES medicines(id)
                    )
                """)
                conn.commit()
                conn.close()
                enc = aes_encrypt(tmp.read_bytes(), self.key)
                _atomic_write_bytes(DB_PATH, enc)
            finally:
                tmp.unlink(missing_ok=True)

    @contextmanager
    def _get_conn(self):
        tmp = _tmp_path("work", ".db")
        try:
            with _CRYPTO_LOCK:
                if DB_PATH.exists():
                    pt = aes_decrypt(DB_PATH.read_bytes(), self.key)
                    _atomic_write_bytes(tmp, pt)
                else:
                    self._ensure_db()
                    pt = aes_decrypt(DB_PATH.read_bytes(), self.key)
                    _atomic_write_bytes(tmp, pt)

            conn = sqlite3.connect(str(tmp))
            conn.row_factory = sqlite3.Row
            yield conn
            conn.close()

            with _CRYPTO_LOCK:
                enc = aes_encrypt(tmp.read_bytes(), self.key)
                _atomic_write_bytes(DB_PATH, enc)
        finally:
            tmp.unlink(missing_ok=True)

    def add_medicine(self, name: str, dosage: str, frequency: str, times: List[str],
                     start_date: str, end_date: str, notes: str) -> int:
        with self._get_conn() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO medicines (name, dosage, frequency, times, start_date, end_date, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, dosage, frequency, json.dumps(times), start_date, end_date, notes))
            conn.commit()
            return c.lastrowid

    def get_medicines(self, active_only=True) -> List[Dict]:
        with self._get_conn() as conn:
            c = conn.cursor()
            if active_only:
                c.execute("SELECT * FROM medicines WHERE active=1 ORDER BY name")
            else:
                c.execute("SELECT * FROM medicines ORDER BY name")
            rows = c.fetchall()
            return [dict(row) for row in rows]

    def update_medicine(self, med_id: int, **kwargs):
        with self._get_conn() as conn:
            c = conn.cursor()
            sets, vals = [], []
            for k, v in kwargs.items():
                sets.append(f"{k}=?")
                vals.append(v)
            vals.append(med_id)
            c.execute(f"UPDATE medicines SET {','.join(sets)} WHERE id=?", vals)
            conn.commit()

    def delete_medicine(self, med_id: int):
        with self._get_conn() as conn:
            c = conn.cursor()
            c.execute("UPDATE medicines SET active=0 WHERE id=?", (med_id,))
            conn.commit()

    def log_dosage(self, med_id: int, scheduled: str, taken: str, status: str):
        with self._get_conn() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO dosage_log (medicine_id, scheduled_time, taken_time, status)
                VALUES (?, ?, ?, ?)
            """, (med_id, scheduled, taken, status))
            conn.commit()

    def get_dosage_log(self, limit=80) -> List[Dict]:
        with self._get_conn() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT d.*, m.name as medicine_name, m.dosage as medicine_dosage
                FROM dosage_log d
                LEFT JOIN medicines m ON d.medicine_id = m.id
                ORDER BY d.scheduled_time DESC
                LIMIT ?
            """, (limit,))
            rows = c.fetchall()
            return [dict(row) for row in rows]

    def get_upcoming_doses(self, hours=36) -> List[Dict]:
        now = datetime.now()
        end = now + timedelta(hours=hours)
        meds = self.get_medicines(active_only=True)

        upcoming = []
        for med in meds:
            times = []
            try:
                times = json.loads(med["times"] or "[]")
            except Exception:
                times = []
            for t in times:
                try:
                    h, m = map(int, t.split(":"))
                    dt = now.replace(hour=h, minute=m, second=0, microsecond=0)
                    if dt < now:
                        dt += timedelta(days=1)
                    if dt <= end:
                        upcoming.append({
                            "medicine_id": med["id"],
                            "name": med["name"],
                            "dosage": med.get("dosage", ""),
                            "time_obj": dt,
                            "time": dt.strftime("%Y-%m-%d %H:%M"),
                            "time_hm": dt.strftime("%H:%M"),
                        })
                except Exception:
                    continue
        upcoming.sort(key=lambda x: x["time"])
        return upcoming

# -------------------------
# Android runtime permissions & AlarmManager scheduling
# -------------------------
def android_sdk_int() -> int:
    if not _android_ready():
        return 0
    try:
        BuildVERSION = autoclass("android.os.Build$VERSION")
        return int(BuildVERSION.SDK_INT)
    except Exception:
        return 0

def ensure_android_notification_permission():
    """
    Android 13+ needs POST_NOTIFICATIONS runtime permission.
    If request fails (OEM quirks), we log and continue; app still works.
    """
    if not _android_ready():
        return
    sdk = android_sdk_int()
    if sdk < 33:
        return
    try:
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        activity = PythonActivity.mActivity
        ContextCompat = autoclass("androidx.core.content.ContextCompat")
        ActivityCompat = autoclass("androidx.core.app.ActivityCompat")
        PackageManager = autoclass("android.content.pm.PackageManager")
        Manifest = autoclass("android.Manifest")

        perm = Manifest.permission.POST_NOTIFICATIONS
        granted = ContextCompat.checkSelfPermission(activity, perm) == PackageManager.PERMISSION_GRANTED
        if not granted:
            ActivityCompat.requestPermissions(activity, [perm], 2407)
            logger.info("requested POST_NOTIFICATIONS permission")
    except Exception:
        logger.exception("POST_NOTIFICATIONS request failed")

def can_schedule_exact_alarms() -> bool:
    """
    Android 12+ has canScheduleExactAlarms().
    We’ll still schedule with a fallback if false.
    """
    if not _android_ready():
        return False
    sdk = android_sdk_int()
    if sdk < 31:
        return True
    try:
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        activity = PythonActivity.mActivity
        Context = autoclass("android.content.Context")
        AlarmManager = autoclass("android.app.AlarmManager")
        am = cast(AlarmManager, activity.getSystemService(Context.ALARM_SERVICE))
        return bool(am.canScheduleExactAlarms())
    except Exception:
        logger.exception("canScheduleExactAlarms check failed")
        return False

class AndroidAlarm:
    @staticmethod
    def schedule(at_time: datetime, title: str, body: str, request_code: int):
        """
        Schedules an AlarmManager broadcast to AlarmReceiver.java (persistent).
        """
        if not _android_ready():
            logger.info(f"[Simulated alarm] {title} - {body} @ {at_time}")
            return

        try:
            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            activity = PythonActivity.mActivity
            app_ctx = activity.getApplicationContext()

            Intent = autoclass("android.content.Intent")
            PendingIntent = autoclass("android.app.PendingIntent")
            AlarmManager = autoclass("android.app.AlarmManager")
            Context = autoclass("android.content.Context")
            Build = autoclass("android.os.Build")

            intent = Intent()
            intent.setClassName(app_ctx, JAVA_ALARM_RECEIVER)
            intent.putExtra("title", title)
            intent.putExtra("body", body)

            flags = PendingIntent.FLAG_UPDATE_CURRENT
            if int(Build.VERSION.SDK_INT) >= 23:
                flags |= PendingIntent.FLAG_IMMUTABLE

            pi = PendingIntent.getBroadcast(app_ctx, int(request_code), intent, int(flags))
            am = cast(AlarmManager, app_ctx.getSystemService(Context.ALARM_SERVICE))

            trigger_ms = int(at_time.timestamp() * 1000)

            # Doze-friendly scheduling:
            if int(Build.VERSION.SDK_INT) >= 23:
                if can_schedule_exact_alarms():
                    am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger_ms, pi)
                    logger.info(f"alarm exact+idle rc={request_code} @ {at_time}")
                else:
                    # Fallback (not guaranteed exact on some devices/versions):
                    am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger_ms, pi)
                    logger.info(f"alarm idle(fallback) rc={request_code} @ {at_time}")
            else:
                am.setExact(AlarmManager.RTC_WAKEUP, trigger_ms, pi)
                logger.info(f"alarm exact rc={request_code} @ {at_time}")
        except Exception:
            logger.exception("alarm scheduling failed")

def stable_alarm_request_code(med_id: int, when_dt: datetime) -> int:
    # Stable per med + date + time (to reduce duplicates)
    key = f"{med_id}|{when_dt.strftime('%Y-%m-%d %H:%M')}"
    h = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(h[:4], "big") & 0x7FFFFFFF

# -------------------------
# (Optional) in-app scheduler thread (desktop / fallback)
# -------------------------
class BackgroundScheduler:
    def __init__(self, db: MedicineDB):
        self.db = db
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        logger.info("background scheduler started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _loop(self):
        while self.running:
            try:
                self._check()
            except Exception:
                logger.exception("background scheduler check failed")
            time.sleep(30)

    def _check(self):
        # Lightweight: if app running, schedule Android alarms periodically
        # (Android side) OR simulate notifications on desktop
        upcoming = self.db.get_upcoming_doses(hours=2)
        now = datetime.now()
        for u in upcoming:
            dt = u["time_obj"]
            if abs((dt - now).total_seconds()) <= 30:
                logger.info(f"[in-app reminder] {u['name']} {u['dosage']} @ {u['time_hm']}")

# -------------------------
# Advanced UI widgets
# -------------------------
class BackgroundGradient(Widget):
    top_color = ListProperty([0.05, 0.15, 0.25, 1])
    bottom_color = ListProperty([0.02, 0.06, 0.12, 1])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw)

    def _redraw(self, *_):
        self.canvas.before.clear()
        x, y = self.pos
        w, h = self.size
        with self.canvas.before:
            bands = 48
            for i in range(bands):
                t = i / (bands - 1)
                r = self.top_color[0] + (self.bottom_color[0] - self.top_color[0]) * t
                g = self.top_color[1] + (self.bottom_color[1] - self.top_color[1]) * t
                b = self.top_color[2] + (self.bottom_color[2] - self.top_color[2]) * t
                Color(r, g, b, 1)
                Rectangle(pos=(x, y + h * i / bands), size=(w, h / bands + 1))

class GlassCard(Widget):
    radius = NumericProperty(dp(22))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw)

    def _redraw(self, *_):
        self.canvas.clear()
        x, y = self.pos
        w, h = self.size
        r = float(self.radius)
        with self.canvas:
            Color(1, 1, 1, 0.06)
            RoundedRectangle(pos=(x, y), size=(w, h), radius=[r])
            Color(1, 1, 1, 0.12)
            Line(rounded_rectangle=[x, y, w, h, r], width=dp(1.2))

class PillIcon(Widget):
    color = ListProperty([0.33, 0.62, 0.95, 1])
    pulse = NumericProperty(0.0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, color=self._redraw, pulse=self._redraw)
        Clock.schedule_once(lambda *_: self._start_pulse(), 0.15)

    def _start_pulse(self):
        anim = (Animation(pulse=1.0, duration=1.1, t="in_out_sine") +
                Animation(pulse=0.0, duration=1.1, t="in_out_sine"))
        anim.repeat = True
        anim.start(self)

    def _redraw(self, *_):
        self.canvas.clear()
        cx, cy = self.center
        w = min(self.width, self.height) * 0.62
        h = min(self.width, self.height) * 0.30
        p = float(self.pulse)
        with self.canvas:
            Color(self.color[0], self.color[1], self.color[2], 0.10 + 0.10 * p)
            Ellipse(pos=(cx - w/2 - dp(6), cy - h/2 - dp(6)), size=(w + dp(12), h + dp(12)))
            Color(*self.color)
            RoundedRectangle(pos=(cx - w/2, cy - h/2), size=(w, h), radius=[h/2])
            Color(1, 1, 1, 0.28)
            Line(rounded_rectangle=[cx - w/2, cy - h/2, w, h, h/2], width=dp(1.4))

# -------------------------
# Kivy KV (Advanced UI + 4 screens)
# -------------------------
KV = """
<BackgroundGradient>:
    size_hint: 1, 1

<GlassCard>:
    size_hint: 1, None

<PillIcon>:
    size_hint: None, None
    size: "54dp", "54dp"

MDScreen:
    MDBoxLayout:
        orientation: "vertical"

        MDTopAppBar:
            title: "Medicine Reminder"
            elevation: 10
            right_action_items: [["refresh", lambda x: app.refresh_all()]]

        ScreenManager:
            id: screen_manager

            MDScreen:
                name: "home"
                BackgroundGradient:
                MDBoxLayout:
                    orientation: "vertical"
                    padding: "12dp"
                    spacing: "12dp"

                    FloatLayout:
                        size_hint_y: None
                        height: "130dp"
                        GlassCard:
                            pos: self.parent.pos
                            size: self.parent.size
                        MDBoxLayout:
                            orientation: "horizontal"
                            padding: "16dp"
                            spacing: "12dp"
                            pos: self.parent.pos
                            size: self.parent.size

                            PillIcon:
                                pos_hint: {"center_y": 0.5}

                            MDBoxLayout:
                                orientation: "vertical"
                                spacing: "4dp"

                                MDLabel:
                                    text: "Next 36 hours"
                                    bold: True
                                    font_style: "H6"

                                MDLabel:
                                    id: today_count
                                    text: "—"
                                    theme_text_color: "Secondary"

                                MDLabel:
                                    id: alarm_status
                                    text: "Alarms: —"
                                    theme_text_color: "Secondary"

                    MDLabel:
                        text: "Upcoming doses (tap to log)"
                        bold: True
                        size_hint_y: None
                        height: "28dp"

                    ScrollView:
                        MDList:
                            id: upcoming_list

                    MDBoxLayout:
                        size_hint_y: None
                        height: "54dp"
                        spacing: "10dp"

                        MDRaisedButton:
                            text: "Add Medicine"
                            on_release: app.show_add_dialog()

                        MDRaisedButton:
                            text: "Resync Alarms"
                            on_release: app.resync_alarms()

            MDScreen:
                name: "medicines"
                BackgroundGradient:
                MDBoxLayout:
                    orientation: "vertical"
                    padding: "12dp"
                    spacing: "12dp"

                    FloatLayout:
                        size_hint_y: None
                        height: "84dp"
                        GlassCard:
                            pos: self.parent.pos
                            size: self.parent.size
                        MDBoxLayout:
                            orientation: "vertical"
                            padding: "14dp"
                            pos: self.parent.pos
                            size: self.parent.size
                            MDLabel:
                                text: "All medicines"
                                bold: True
                                font_style: "H6"
                            MDLabel:
                                id: med_count
                                text: "—"
                                theme_text_color: "Secondary"

                    ScrollView:
                        MDList:
                            id: medicines_list

            MDScreen:
                name: "history"
                BackgroundGradient:
                MDBoxLayout:
                    orientation: "vertical"
                    padding: "12dp"
                    spacing: "12dp"

                    FloatLayout:
                        size_hint_y: None
                        height: "84dp"
                        GlassCard:
                            pos: self.parent.pos
                            size: self.parent.size
                        MDBoxLayout:
                            orientation: "vertical"
                            padding: "14dp"
                            pos: self.parent.pos
                            size: self.parent.size
                            MDLabel:
                                text: "Dose history"
                                bold: True
                                font_style: "H6"
                            MDLabel:
                                id: hist_count
                                text: "—"
                                theme_text_color: "Secondary"

                    ScrollView:
                        MDList:
                            id: history_list

                    MDRaisedButton:
                        text: "Refresh"
                        size_hint_y: None
                        height: "48dp"
                        on_release: app.refresh_history()

            MDScreen:
                name: "settings"
                BackgroundGradient:
                MDBoxLayout:
                    orientation: "vertical"
                    padding: "12dp"
                    spacing: "12dp"

                    FloatLayout:
                        size_hint_y: None
                        height: "84dp"
                        GlassCard:
                            pos: self.parent.pos
                            size: self.parent.size
                        MDBoxLayout:
                            orientation: "vertical"
                            padding: "14dp"
                            pos: self.parent.pos
                            size: self.parent.size
                            MDLabel:
                                text: "Settings & Logs"
                                bold: True
                                font_style: "H6"
                            MDLabel:
                                id: db_status
                                text: "—"
                                theme_text_color: "Secondary"

                    MDLabel:
                        text: "Debug log"
                        bold: True
                        size_hint_y: None
                        height: "28dp"

                    ScrollView:
                        MDLabel:
                            id: debug_log
                            text: ""
                            size_hint_y: None
                            height: self.texture_size[1]

                    MDBoxLayout:
                        spacing: "10dp"
                        size_hint_y: None
                        height: "48dp"
                        MDRaisedButton:
                            text: "Refresh Log"
                            on_release: app.refresh_log()
                        MDRaisedButton:
                            text: "Clear Log"
                            on_release: app.clear_log()

        MDBottomNavigation:
            panel_color: 0.05, 0.08, 0.12, 1
            MDBottomNavigationItem:
                name: "nav_home"
                text: "Home"
                icon: "home"
                on_tab_press: app.switch_screen("home")
            MDBottomNavigationItem:
                name: "nav_medicines"
                text: "Medicines"
                icon: "pill"
                on_tab_press: app.switch_screen("medicines")
            MDBottomNavigationItem:
                name: "nav_history"
                text: "History"
                icon: "history"
                on_tab_press: app.switch_screen("history")
            MDBottomNavigationItem:
                name: "nav_settings"
                text: "Settings"
                icon: "cog"
                on_tab_press: app.switch_screen("settings")
"""

# -------------------------
# Android source generator (Buildozer)
# -------------------------
JAVA_ALARM_RECEIVER_SRC = r"""
package {JAVA_PACKAGE};

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

public class AlarmReceiver extends BroadcastReceiver {{
    private static final String CHANNEL_ID = "medicine_reminders";

    @Override
    public void onReceive(Context context, Intent intent) {{
        String title = intent.getStringExtra("title");
        String body = intent.getStringExtra("body");
        if (title == null) title = "Medicine Reminder";
        if (body == null) body = "Time to take your medicine";

        NotificationManager nm =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

        if (Build.VERSION.SDK_INT >= 26) {{
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID,
                    "Medicine Reminders",
                    NotificationManager.IMPORTANCE_HIGH
            );
            ch.setDescription("Scheduled medicine reminders");
            nm.createNotificationChannel(ch);
        }}

        Notification.Builder b = (Build.VERSION.SDK_INT >= 26)
                ? new Notification.Builder(context, CHANNEL_ID)
                : new Notification.Builder(context);

        b.setContentTitle(title)
         .setContentText(body)
         .setSmallIcon(context.getApplicationInfo().icon)
         .setAutoCancel(true);

        int nid = (int)(System.currentTimeMillis() & 0x7fffffff);
        nm.notify(nid, b.build());
    }}
}}
"""

JAVA_BOOT_RECEIVER_SRC = r"""
package {JAVA_PACKAGE};

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class BootReceiver extends BroadcastReceiver {{
    @Override
    public void onReceive(Context context, Intent intent) {{
        // Launch app so Python can resync alarms from encrypted DB.
        Intent launch = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
        if (launch != null) {{
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(launch);
        }}
    }}
}}
"""

EXTRA_MANIFEST_XML = r"""<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.SCHEDULE_EXACT_ALARM"/>
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.VIBRATE"/>

    <application>
        <receiver
            android:name="{JAVA_PACKAGE}.AlarmReceiver"
            android:exported="false" />

        <receiver
            android:name="{JAVA_PACKAGE}.BootReceiver"
            android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
                <action android:name="android.intent.action.LOCKED_BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
"""

def write_android_sources(out_dir: Path):
    pkg_path = Path(*JAVA_PACKAGE.split("."))
    src_root = out_dir / "android_src"
    java_dir = src_root / pkg_path
    java_dir.mkdir(parents=True, exist_ok=True)

    (java_dir / "AlarmReceiver.java").write_text(
        JAVA_ALARM_RECEIVER_SRC.format(JAVA_PACKAGE=JAVA_PACKAGE),
        encoding="utf-8"
    )
    (java_dir / "BootReceiver.java").write_text(
        JAVA_BOOT_RECEIVER_SRC.format(JAVA_PACKAGE=JAVA_PACKAGE),
        encoding="utf-8"
    )
    (src_root / "extra_manifest.xml").write_text(
        EXTRA_MANIFEST_XML.format(JAVA_PACKAGE=JAVA_PACKAGE),
        encoding="utf-8"
    )
    print(f"[gen] Wrote android sources to: {src_root}")
    print("[gen] In buildozer.spec set:")
    print("      android.add_src = android_src")
    print("      android.extra_manifest_xml = android_src/extra_manifest.xml")

# -------------------------
# App
# -------------------------
class MedicineReminderApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.db: Optional[MedicineDB] = None
        self.scheduler: Optional[BackgroundScheduler] = None
        self._add_dialog: Optional[MDDialog] = None
        self._edit_dialog: Optional[MDDialog] = None

        # temp dialog fields
        self._time_list: List[str] = []

    def build(self):
        self.title = "Medicine Reminder"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Blue"
        return Builder.load_string(KV)

    def on_start(self):
        logger.info(f"app start platform={_kivy_platform} base={BASE_DIR}")

        ensure_android_notification_permission()

        key = get_or_create_key()
        self.db = MedicineDB(key)

        # In-app scheduler is mainly for desktop; on Android we still run it lightly.
        self.scheduler = BackgroundScheduler(self.db)
        self.scheduler.start()

        self.root.ids.screen_manager.current = "home"
        Clock.schedule_once(lambda *_: self.refresh_all(), 0.4)

        # Periodic UI refresh
        Clock.schedule_interval(lambda *_: self.refresh_upcoming(), 60)
        Clock.schedule_interval(lambda *_: self.refresh_log(silent=True), 20)

        # Periodic alarm resync (Android): keep next 36h scheduled
        Clock.schedule_interval(lambda *_: self.resync_alarms(silent=True), 60 * 15)

        # initial alarm sync
        Clock.schedule_once(lambda *_: self.resync_alarms(silent=True), 1.0)

    def on_stop(self):
        try:
            if self.scheduler:
                self.scheduler.stop()
        except Exception:
            pass

    # -------------------------
    # Navigation
    # -------------------------
    def switch_screen(self, name: str):
        self.root.ids.screen_manager.current = name
        if name == "home":
            self.refresh_upcoming()
        elif name == "medicines":
            self.refresh_medicines()
        elif name == "history":
            self.refresh_history()
        elif name == "settings":
            self.refresh_log()

    # -------------------------
    # Refresh
    # -------------------------
    def refresh_all(self):
        self.refresh_upcoming()
        self.refresh_medicines()
        self.refresh_history()
        self.refresh_log(silent=True)

    def refresh_upcoming(self):
        if not self.db:
            return
        try:
            upcoming = self.db.get_upcoming_doses(hours=36)
            ul = self.root.ids.upcoming_list
            ul.clear_widgets()

            for u in upcoming:
                text = f"{u['name']}  •  {u.get('dosage','')}".strip()
                sub = f"{u['time']}"

                item = TwoLineIconListItem(text=text, secondary_text=sub)
                item.add_widget(IconLeftWidget(icon="clock-outline"))

                # tap to log taken/skip
                item.on_release = lambda u=u: self.show_log_dose_dialog(u)
                ul.add_widget(item)

            self.root.ids.today_count.text = f"{len(upcoming)} doses scheduled"

            if _android_ready():
                exact = can_schedule_exact_alarms()
                self.root.ids.alarm_status.text = f"Alarms: {'Exact' if exact else 'Fallback'}"
            else:
                self.root.ids.alarm_status.text = "Alarms: Desktop (simulated)"
        except Exception:
            logger.exception("refresh_upcoming failed")

    def refresh_medicines(self):
        if not self.db:
            return
        try:
            meds = self.db.get_medicines(active_only=True)
            ml = self.root.ids.medicines_list
            ml.clear_widgets()

            for m in meds:
                times = ""
                try:
                    times = ", ".join(json.loads(m.get("times") or "[]"))
                except Exception:
                    times = ""
                item = TwoLineIconListItem(
                    text=f"{m['name']} ({m.get('dosage','')})".strip(),
                    secondary_text=f"{times}".strip()
                )
                item.add_widget(IconLeftWidget(icon="pill"))
                item.on_release = lambda m_id=m["id"]: self.show_edit_dialog(m_id)
                ml.add_widget(item)

            self.root.ids.med_count.text = f"{len(meds)} medicines"
        except Exception:
            logger.exception("refresh_medicines failed")

    def refresh_history(self):
        if not self.db:
            return
        try:
            logs = self.db.get_dosage_log(limit=80)
            hl = self.root.ids.history_list
            hl.clear_widgets()

            for l in logs:
                name = l.get("medicine_name") or "Unknown"
                dosage = l.get("medicine_dosage") or ""
                status = l.get("status") or "—"
                sched = (l.get("scheduled_time") or "")[:16]
                taken = (l.get("taken_time") or "—")[:16]
                item = TwoLineIconListItem(
                    text=f"{name} {dosage} • {status}".strip(),
                    secondary_text=f"{sched} → {taken}"
                )
                item.add_widget(IconLeftWidget(icon="history"))
                hl.add_widget(item)

            self.root.ids.hist_count.text = f"{len(logs)} entries"
        except Exception:
            logger.exception("refresh_history failed")

    def refresh_log(self, silent: bool = False):
        try:
            if not silent:
                logger.info("log refreshed")
            self.root.ids.debug_log.text = _RING.text()

            if DB_PATH.exists():
                kb = DB_PATH.stat().st_size / 1024.0
                self.root.ids.db_status.text = f"Encrypted DB: {kb:.1f} KB  •  Base: {BASE_DIR}"
            else:
                self.root.ids.db_status.text = f"DB not found  •  Base: {BASE_DIR}"
        except Exception:
            logger.exception("refresh_log failed")

    def clear_log(self):
        _RING.clear()
        try:
            LOG_PATH.unlink(missing_ok=True)
        except Exception:
            pass
        self.root.ids.debug_log.text = ""
        logger.info("log cleared")

    # -------------------------
    # Alarm resync (Android persistent alarms)
    # -------------------------
    def resync_alarms(self, silent: bool = False):
        if not self.db:
            return
        with _SCHEDULE_LOCK:
            try:
                upcoming = self.db.get_upcoming_doses(hours=36)
                if _android_ready():
                    # Schedule each upcoming dose as an alarm
                    for u in upcoming:
                        dt = u["time_obj"]
                        rc = stable_alarm_request_code(u["medicine_id"], dt)
                        title = "Medicine Reminder"
                        body = f"{u['name']} • {u.get('dosage','')}".strip()
                        AndroidAlarm.schedule(dt, title, body, rc)
                    if not silent:
                        logger.info(f"resynced alarms for {len(upcoming)} doses")
                else:
                    if not silent:
                        logger.info("resync alarms: desktop (no-op)")
            except Exception:
                logger.exception("resync_alarms failed")

    # -------------------------
    # Dose logging dialog
    # -------------------------
    def show_log_dose_dialog(self, upcoming_item: Dict):
        if not self.db:
            return

        med_id = int(upcoming_item["medicine_id"])
        sched = upcoming_item["time"]
        title = f"{upcoming_item['name']} • {upcoming_item.get('dosage','')}".strip()

        def log(status: str):
            try:
                taken = datetime.now().strftime("%Y-%m-%d %H:%M")
                self.db.log_dosage(med_id, scheduled=sched, taken=taken, status=status)
                logger.info(f"dose log: med_id={med_id} {status} sched={sched} taken={taken}")
                self.refresh_history()
                self.refresh_upcoming()
            except Exception:
                logger.exception("log dosage failed")

        dialog = MDDialog(
            title="Log dose",
            text=f"{title}\nScheduled: {sched}",
            buttons=[
                MDFlatButton(text="Skip", on_release=lambda *_: (log("skipped"), dialog.dismiss())),
                MDFlatButton(text="Late", on_release=lambda *_: (log("taken_late"), dialog.dismiss())),
                MDRaisedButton(text="Taken", on_release=lambda *_: (log("taken"), dialog.dismiss())),
            ]
        )
        dialog.open()

    # -------------------------
    # Add / Edit medicine dialogs (with time picker)
    # -------------------------
    def show_add_dialog(self):
        self._time_list = []

        content = MDBoxLayout(orientation="vertical", spacing="10dp", padding="10dp", size_hint_y=None)
        content.bind(minimum_height=content.setter("height"))

        name = MDTextField(hint_text="Medicine name", helper_text="Required", helper_text_mode="on_error")
        dosage = MDTextField(hint_text="Dosage (e.g., 500mg)")
        frequency = MDTextField(hint_text="Frequency (e.g., daily, every 8h)", text="daily")
        start_date = MDTextField(hint_text="Start date (YYYY-MM-DD)", text=datetime.now().strftime("%Y-%m-%d"))
        end_date = MDTextField(hint_text="End date (YYYY-MM-DD) optional", text="")
        notes = MDTextField(hint_text="Notes (optional)")

        times_label = MDLabel(text="Times", bold=True, size_hint_y=None, height="24dp")
        times_box = MDBoxLayout(orientation="vertical", spacing="6dp", size_hint_y=None)
        times_box.bind(minimum_height=times_box.setter("height"))

        def redraw_times():
            times_box.clear_widgets()
            if not self._time_list:
                times_box.add_widget(MDLabel(text="No times added", theme_text_color="Secondary",
                                             size_hint_y=None, height="22dp"))
                return
            for t in self._time_list:
                row = MDBoxLayout(orientation="horizontal", spacing="8dp", size_hint_y=None, height="38dp")
                row.add_widget(MDLabel(text=t, size_hint_x=1))
                btn = MDIconButton(icon="close", on_release=lambda _, t=t: remove_time(t))
                row.add_widget(btn)
                times_box.add_widget(row)

        def add_time_from_picker(*_):
            picker = MDTimePicker()
            def on_ok(_, time_obj):
                t = f"{time_obj.hour:02d}:{time_obj.minute:02d}"
                if t not in self._time_list:
                    self._time_list.append(t)
                    self._time_list.sort()
                redraw_times()
            picker.bind(time=on_ok)
            picker.open()

        def remove_time(t: str):
            try:
                self._time_list = [x for x in self._time_list if x != t]
                redraw_times()
            except Exception:
                pass

        add_time_btn = MDRaisedButton(text="Add time", on_release=add_time_from_picker)

        for w in (name, dosage, frequency, start_date, end_date, notes, times_label, times_box, add_time_btn):
            content.add_widget(w)

        redraw_times()

        def save(*_):
            try:
                if not name.text.strip():
                    name.error = True
                    return
                times = list(self._time_list)
                if not times:
                    # sensible default
                    times = ["09:00"]
                med_id = self.db.add_medicine(
                    name=name.text.strip(),
                    dosage=dosage.text.strip(),
                    frequency=frequency.text.strip() or "daily",
                    times=times,
                    start_date=start_date.text.strip(),
                    end_date=end_date.text.strip(),
                    notes=notes.text.strip()
                )
                logger.info(f"added medicine id={med_id} {name.text.strip()} times={times}")
                self._add_dialog.dismiss()
                self.refresh_all()
                self.resync_alarms(silent=True)
            except Exception:
                logger.exception("add medicine failed")

        self._add_dialog = MDDialog(
            title="Add medicine",
            type="custom",
            content_cls=content,
            buttons=[
                MDFlatButton(text="Cancel", on_release=lambda *_: self._add_dialog.dismiss()),
                MDRaisedButton(text="Save", on_release=save),
            ]
        )
        self._add_dialog.open()

    def show_edit_dialog(self, med_id: int):
        if not self.db:
            return
        meds = self.db.get_medicines(active_only=False)
        med = next((m for m in meds if int(m["id"]) == int(med_id)), None)
        if not med:
            return

        try:
            self._time_list = sorted(list(json.loads(med.get("times") or "[]")))
        except Exception:
            self._time_list = []

        content = MDBoxLayout(orientation="vertical", spacing="10dp", padding="10dp", size_hint_y=None)
        content.bind(minimum_height=content.setter("height"))

        name = MDTextField(hint_text="Medicine name", text=med.get("name") or "")
        dosage = MDTextField(hint_text="Dosage", text=med.get("dosage") or "")
        frequency = MDTextField(hint_text="Frequency", text=med.get("frequency") or "daily")
        start_date = MDTextField(hint_text="Start date", text=med.get("start_date") or "")
        end_date = MDTextField(hint_text="End date", text=med.get("end_date") or "")
        notes = MDTextField(hint_text="Notes", text=med.get("notes") or "")

        times_label = MDLabel(text="Times", bold=True, size_hint_y=None, height="24dp")
        times_box = MDBoxLayout(orientation="vertical", spacing="6dp", size_hint_y=None)
        times_box.bind(minimum_height=times_box.setter("height"))

        def redraw_times():
            times_box.clear_widgets()
            if not self._time_list:
                times_box.add_widget(MDLabel(text="No times added", theme_text_color="Secondary",
                                             size_hint_y=None, height="22dp"))
                return
            for t in self._time_list:
                row = MDBoxLayout(orientation="horizontal", spacing="8dp", size_hint_y=None, height="38dp")
                row.add_widget(MDLabel(text=t, size_hint_x=1))
                btn = MDIconButton(icon="close", on_release=lambda _, t=t: remove_time(t))
                row.add_widget(btn)
                times_box.add_widget(row)

        def add_time_from_picker(*_):
            picker = MDTimePicker()
            def on_ok(_, time_obj):
                t = f"{time_obj.hour:02d}:{time_obj.minute:02d}"
                if t not in self._time_list:
                    self._time_list.append(t)
                    self._time_list.sort()
                redraw_times()
            picker.bind(time=on_ok)
            picker.open()

        def remove_time(t: str):
            self._time_list = [x for x in self._time_list if x != t]
            redraw_times()

        add_time_btn = MDRaisedButton(text="Add time", on_release=add_time_from_picker)

        for w in (name, dosage, frequency, start_date, end_date, notes, times_label, times_box, add_time_btn):
            content.add_widget(w)

        redraw_times()

        def save(*_):
            try:
                times = list(self._time_list) or ["09:00"]
                self.db.update_medicine(
                    int(med_id),
                    name=name.text.strip(),
                    dosage=dosage.text.strip(),
                    frequency=frequency.text.strip() or "daily",
                    times=json.dumps(times),
                    start_date=start_date.text.strip(),
                    end_date=end_date.text.strip(),
                    notes=notes.text.strip()
                )
                logger.info(f"updated medicine id={med_id} times={times}")
                self._edit_dialog.dismiss()
                self.refresh_all()
                self.resync_alarms(silent=True)
            except Exception:
                logger.exception("update medicine failed")

        def delete(*_):
            try:
                self.db.delete_medicine(int(med_id))
                logger.info(f"deleted medicine id={med_id}")
                self._edit_dialog.dismiss()
                self.refresh_all()
                self.resync_alarms(silent=True)
            except Exception:
                logger.exception("delete medicine failed")

        self._edit_dialog = MDDialog(
            title="Edit medicine",
            type="custom",
            content_cls=content,
            buttons=[
                MDFlatButton(text="Delete", on_release=delete),
                MDFlatButton(text="Cancel", on_release=lambda *_: self._edit_dialog.dismiss()),
                MDRaisedButton(text="Save", on_release=save),
            ]
        )
        self._edit_dialog.open()

# -------------------------
# Entrypoint
# -------------------------
def main():
    if "--gen-android" in sys.argv:
        write_android_sources(Path.cwd())
        return

    MedicineReminderApp().run()

if __name__ == "__main__":
    main()
```0
