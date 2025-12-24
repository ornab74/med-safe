# service/med_service.py
import os
import json
import time
import uuid
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

try:
    from jnius import autoclass
except Exception:
    autoclass = None


CHUNK = 1024 * 1024


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


def _atomic_write(path: Path, data: bytes):
    tmp = path.with_suffix(path.suffix + f".tmp.{uuid.uuid4().hex}")
    tmp.write_bytes(data)
    tmp.replace(path)


def _android_files_dir() -> Optional[Path]:
    """
    Resolve app-private files dir from the service process.
    """
    if autoclass is None:
        return None
    try:
        PythonService = autoclass("org.kivy.android.PythonService")
        svc = PythonService.mService
        if svc is None:
            return None
        d = svc.getFilesDir().getAbsolutePath()
        return Path(str(d))
    except Exception:
        return None


class Vault:
    """
    Minimal encrypted vault for meds (shared between app + service).
    Stored in app-private files dir so the service can read it.
    """
    def __init__(self, base_dir: Path):
        self.base = base_dir / "medsafe_data"
        self.base.mkdir(parents=True, exist_ok=True)
        self.install_master_path = self.base / ".install_master_key"
        self.vault_wrap_path = self.base / ".vault_mdk.wrap"
        self.meds_path = self.base / "meds.json.aes"

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
            # first boot: create master + mdk
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
            # corrupted wrap -> reset (service keeps going)
            mdk = os.urandom(32)
            _atomic_write(self.vault_wrap_path, encrypt_bytes_gcm(mdk, master))
            return mdk

        if len(mdk) != 32:
            mdk = os.urandom(32)
            _atomic_write(self.vault_wrap_path, encrypt_bytes_gcm(mdk, master))
        return mdk

    def load_meds(self) -> Dict[str, Any]:
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


def _now() -> float:
    return time.time()


def _fmt_mins(m: float) -> str:
    m = max(0.0, m)
    if m < 90:
        return f"{int(round(m))} min"
    h = m / 60.0
    if h < 48:
        return f"{h:.1f} hr"
    d = h / 24.0
    return f"{d:.1f} d"


def compute_due(med: Dict[str, Any], now_ts: float) -> Tuple[bool, float]:
    """
    Returns (is_due, minutes_over_or_under)
      - if due:  minutes_over >= 0  (how overdue)
      - if not:  minutes_over is negative (how many minutes until due)
    """
    interval_h = float(med.get("interval_hours") or 0.0)
    if interval_h <= 0.0:
        return (False, -999999.0)

    last_taken = float(med.get("last_taken_ts") or 0.0)
    if last_taken <= 0.0:
        # never taken => treat as due now
        return (True, 0.0)

    next_due = last_taken + interval_h * 3600.0
    delta_sec = now_ts - next_due
    return (delta_sec >= 0.0, delta_sec / 60.0)


def due_risk_level(minutes_over: float) -> str:
    """
    Overdue severity -> Low/Medium/High
    """
    if minutes_over < 0:
        # not due yet
        return "Low"
    if minutes_over >= 240:   # 4h+
        return "High"
    if minutes_over >= 60:    # 1h+
        return "Medium"
    return "Low"


def _ensure_channel():
    """
    Create NotificationChannel on Android O+ (best-effort).
    """
    if autoclass is None:
        return
    try:
        Build_VERSION = autoclass("android.os.Build$VERSION")
        if int(Build_VERSION.SDK_INT) < 26:
            return

        PythonService = autoclass("org.kivy.android.PythonService")
        svc = PythonService.mService
        if svc is None:
            return

        Context = autoclass("android.content.Context")
        NotificationChannel = autoclass("android.app.NotificationChannel")
        NotificationManager = autoclass("android.app.NotificationManager")

        nm = svc.getSystemService(Context.NOTIFICATION_SERVICE)
        channel_id = "medsafe_reminders"
        name = "MedSafe Reminders"
        importance = NotificationManager.IMPORTANCE_DEFAULT
        ch = NotificationChannel(channel_id, name, importance)
        nm.createNotificationChannel(ch)
    except Exception:
        pass


def notify(title: str, text: str, notif_id: int = 1001):
    """
    Post a notification (best-effort).
    """
    if autoclass is None:
        return
    try:
        _ensure_channel()

        PythonService = autoclass("org.kivy.android.PythonService")
        svc = PythonService.mService
        if svc is None:
            return

        Context = autoclass("android.content.Context")
        NotificationManager = autoclass("android.app.NotificationManager")

        nm = svc.getSystemService(Context.NOTIFICATION_SERVICE)

        # Use NotificationCompat for broad compatibility
        NotificationCompatBuilder = autoclass("androidx.core.app.NotificationCompat$Builder")
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        Intent = autoclass("android.content.Intent")
        PendingIntent = autoclass("android.app.PendingIntent")

        app_context = svc.getApplicationContext()
        pkg = app_context.getPackageName()

        intent = Intent(app_context, PythonActivity)
        intent.setAction(Intent.ACTION_MAIN)
        intent.addCategory(Intent.CATEGORY_LAUNCHER)
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        # FLAG_IMMUTABLE is recommended, but some p4a stacks differ; keep 0 for compatibility
        pi = PendingIntent.getActivity(svc, 0, intent, 0)

        # small icon must exist as a drawable; "icon" is commonly present in p4a builds
        Drawable = autoclass(f"{pkg}.R$drawable")
        try:
            small_icon = getattr(Drawable, "icon")
        except Exception:
            small_icon = 0

        builder = NotificationCompatBuilder(app_context, "medsafe_reminders")
        builder.setContentTitle(title)
        builder.setContentText(text)
        builder.setSmallIcon(small_icon)
        builder.setContentIntent(pi)
        builder.setAutoCancel(True)

        nm.notify(notif_id, builder.build())
    except Exception:
        pass


def promote_to_foreground():
    """
    Foreground service notification (persistent).
    Kivy wiki shows the PythonService.mService route 5.
    """
    if autoclass is None:
        return
    try:
        PythonService = autoclass("org.kivy.android.PythonService")
        svc = PythonService.mService
        if svc is None:
            return

        # best-effort "keep alive" notification
        _ensure_channel()
        notify("MedSafe", "Reminders running in background", notif_id=42)

        # Optional: auto-restart if the OS kills it (documented by p4a) 6
        try:
            PythonService.mService.setAutoRestartService(True)
        except Exception:
            pass
    except Exception:
        pass


def main_loop():
    files_dir = _android_files_dir()
    if files_dir is None:
        # No android context; just exit quietly
        return

    vault = Vault(files_dir)
    promote_to_foreground()

    # Rate limiting: don’t spam the same med every tick
    last_sent: Dict[str, float] = {}  # med_id -> ts

    while True:
        now_ts = _now()
        data = vault.load_meds()
        meds: List[Dict[str, Any]] = list(data.get("meds") or [])

        for med in meds:
            med_id = str(med.get("id") or "")
            if not med_id:
                continue

            is_due, mins_over = compute_due(med, now_ts)
            if not is_due:
                continue

            lvl = due_risk_level(mins_over)
            # Send if not sent recently (per med)
            prev = float(last_sent.get(med_id) or 0.0)
            if now_ts - prev < 20 * 60:
                continue

            name = str(med.get("name") or "Medication")
            dose = float(med.get("dose_mg") or 0.0)
            msg = f"{name}: {dose:g} mg due ({lvl}) — overdue {_fmt_mins(mins_over)}"
            notify("MedSafe Reminder", msg, notif_id=1000 + (hash(med_id) % 5000))
            last_sent[med_id] = now_ts

        time.sleep(30.0)


if __name__ == "__main__":
    main_loop()
