# service/med_service.py
import os, time, json, uuid, sqlite3, logging
from pathlib import Path
from datetime import datetime, timedelta
from threading import RLock
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

try:
    from jnius import autoclass
except Exception:
    autoclass = None

_CRYPTO_LOCK = RLock()

def _android_files_dir() -> Path:
    PythonService = autoclass("org.kivy.android.PythonService")
    service = PythonService.mService
    d = service.getFilesDir().getAbsolutePath()
    return Path(str(d))

def _app_base_dir() -> Path:
    # Match main.py: under app files dir
    base = _android_files_dir()
    d = base / "medreminder_data"
    d.mkdir(parents=True, exist_ok=True)
    return d

BASE_DIR = _app_base_dir()
DB_PATH = BASE_DIR / "medicines.db.aes"
KEY_PATH = BASE_DIR / ".enc_key"
TMP_DIR = BASE_DIR / "tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    if not data or len(data) < 12:
        raise InvalidTag("ciphertext too short")
    aes = AESGCM(key)
    nonce, ct = data[:12], data[12:]
    return aes.decrypt(nonce, ct, None)

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data, None)

def _tmp_path(prefix: str, suffix: str) -> Path:
    return TMP_DIR / f"{prefix}.{uuid.uuid4().hex}{suffix}"

def load_key() -> bytes:
    return KEY_PATH.read_bytes()[:32]

class MedicineDB:
    def __init__(self, key: bytes):
        self.key = key

    def _ensure_db(self):
        if DB_PATH.exists():
            return
        # service won't create schema; UI app should create it
        raise RuntimeError("DB missing - open app once to initialize.")

    def get_upcoming_doses(self, hours=6):
        self._ensure_db()
        now = datetime.now()
        end = now + timedelta(hours=hours)

        tmp = _tmp_path("work", ".db")
        try:
            with _CRYPTO_LOCK:
                pt = aes_decrypt(DB_PATH.read_bytes(), self.key)
                tmp.write_bytes(pt)

            conn = sqlite3.connect(str(tmp))
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM medicines WHERE active=1").fetchall()
            conn.close()

            upcoming = []
            for med in [dict(r) for r in rows]:
                try:
                    times = json.loads(med.get("times") or "[]")
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
                                "time_hm": dt.strftime("%H:%M"),
                                "time": dt.strftime("%Y-%m-%d %H:%M"),
                            })
                    except Exception:
                        continue

            upcoming.sort(key=lambda x: x["time"])
            return upcoming
        finally:
            tmp.unlink(missing_ok=True)

def notify(title: str, text: str):
    if autoclass is None:
        return
    try:
        PythonService = autoclass("org.kivy.android.PythonService")
        service = PythonService.mService
        Context = autoclass("android.content.Context")
        NotificationManager = autoclass("android.app.NotificationManager")
        NotificationChannel = autoclass("android.app.NotificationChannel")
        Notification = autoclass("android.app.Notification")
        Build = autoclass("android.os.Build")

        channel_id = "medsafe_reminders"
        nm = service.getSystemService(Context.NOTIFICATION_SERVICE)

        if Build.VERSION.SDK_INT >= 26:
            ch = NotificationChannel(channel_id, "MedSafe Reminders", NotificationManager.IMPORTANCE_HIGH)
            ch.setDescription("Medicine reminders from MedSafe background service")
            nm.createNotificationChannel(ch)
            builder = Notification.Builder(service, channel_id)
        else:
            builder = Notification.Builder(service)

        builder.setContentTitle(title)
        builder.setContentText(text)
        builder.setSmallIcon(service.getApplicationInfo().icon)
        builder.setAutoCancel(True)

        nid = int(time.time()) & 0x7fffffff
        nm.notify(nid, builder.build())
    except Exception:
        pass

def main_loop():
    key = load_key()
    db = MedicineDB(key)

    # to avoid repeat spam, keep last-fired per medicine/time
    fired = {}  # key: (med_id, yyyy-mm-dd hh:mm) -> last_ts

    while True:
        try:
            upcoming = db.get_upcoming_doses(hours=3)
            now = datetime.now()

            for u in upcoming:
                dt = u["time_obj"]
                diff = (dt - now).total_seconds()

                # Fire within this window: 0..45 seconds late/early tolerance
                if -20 <= diff <= 45:
                    k = (u["medicine_id"], u["time"])
                    last = fired.get(k, 0)
                    if time.time() - last > 90:  # avoid duplicates
                        fired[k] = time.time()
                        notify("MedSafe Reminder", f"{u['name']} • {u.get('dosage','')} @ {u['time_hm']}".strip())

        except Exception:
            # DB might not exist until app opened once
            pass

        time.sleep(20)

if __name__ == "__main__":
    main_loop()
