import os
import json
import time
import uuid
import threading
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from kivy.lang import Builder
from kivy.clock import Clock
from kivy.utils import platform as _kivy_platform

from kivymd.app import MDApp
from kivymd.uix.appbar import MDTopAppBar  # NEW KIVYMD
from kivymd.uix.list import OneLineListItem

# Optional Android files dir (Context.getFilesDir)
try:
    from jnius import autoclass
except Exception:
    autoclass = None

logger = logging.getLogger("medsafe")
logging.basicConfig(level=logging.INFO)


KV = r"""
MDScreen:
    MDBoxLayout:
        orientation: "vertical"

        MDTopAppBar:
            id: topbar
            title: "MedSafe (Prototype)"
            elevation: 6
            right_action_items:
                [
                ["bug-outline", lambda x: app.show_debug()],
                ["refresh", lambda x: app.refresh_meds()]
                ]

        MDBoxLayout:
            orientation: "vertical"
            padding: "14dp"
            spacing: "12dp"

            MDLabel:
                id: status
                text: "Status: Ready"
                halign: "center"
                theme_text_color: "Secondary"
                size_hint_y: None
                height: "24dp"

            MDLabel:
                id: risk
                text: "Risk: —"
                halign: "center"
                theme_text_color: "Primary"
                font_size: "20sp"
                size_hint_y: None
                height: "34dp"

            MDLabel:
                id: selected
                text: "Selected: —"
                halign: "center"
                theme_text_color: "Secondary"
                size_hint_y: None
                height: "22dp"

            MDBoxLayout:
                orientation: "vertical"
                spacing: "10dp"
                size_hint_y: None
                height: self.minimum_height

                MDTextField:
                    id: med_name
                    hint_text: "Medication name"

                MDTextField:
                    id: dose_mg
                    hint_text: "Dose (mg) e.g. 200"
                    input_filter: "float"

                MDTextField:
                    id: interval_h
                    hint_text: "Interval hours e.g. 8"
                    input_filter: "float"

                MDTextField:
                    id: max_daily
                    hint_text: "Max daily mg (optional) e.g. 1200"
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
                    height: "40dp"
                    spacing: "10dp"

                    MDFlatButton:
                        text: "Delete Selected"
                        on_release: app.on_delete_med()

                    Widget:

                    MDFlatButton:
                        text: "Clear Risk"
                        on_release: app.clear_risk()

            MDLabel:
                text: "Medications"
                halign: "left"
                theme_text_color: "Primary"
                size_hint_y: None
                height: "24dp"

            ScrollView:
                do_scroll_x: False

                MDList:
                    id: med_list
"""


# ---------------------------
# Crypto (AES-GCM)
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


def _atomic_write(path: Path, data: bytes):
    tmp = path.with_suffix(path.suffix + f".tmp.{uuid.uuid4().hex}")
    tmp.write_bytes(data)
    tmp.replace(path)


def _android_files_dir() -> Optional[Path]:
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


class Vault:
    """
    Encrypted JSON vault:
      - base/.vault_key (random secret)
      - meds.json.aes
    """
    def __init__(self, base_dir: Path):
        self.base = base_dir / "medsafe_data"
        self.base.mkdir(parents=True, exist_ok=True)
        self.key_path = self.base / ".vault_key"
        self.data_path = self.base / "meds.json.aes"
        self.lock = threading.Lock()

    def _get_key(self) -> bytes:
        if self.key_path.exists():
            k = self.key_path.read_bytes()
            if len(k) >= 32:
                return k[:32]
        k = os.urandom(32)
        _atomic_write(self.key_path, k)
        return k

    def load(self) -> Dict[str, Any]:
        with self.lock:
            key = self._get_key()
            if not self.data_path.exists():
                return {"version": 1, "meds": []}
            try:
                blob = self.data_path.read_bytes()
                pt = decrypt_bytes_gcm(blob, key)
                # STRICT utf-8 decode; if corrupted, fail cleanly (don’t mojibake/ignore)
                obj = json.loads(pt.decode("utf-8") or "{}")
                if not isinstance(obj, dict):
                    return {"version": 1, "meds": []}
                obj.setdefault("version", 1)
                obj.setdefault("meds", [])
                return obj
            except Exception as e:
                logger.exception("Vault load failed: %s", e)
                return {"version": 1, "meds": []}

    def save(self, obj: Dict[str, Any]):
        with self.lock:
            key = self._get_key()
            raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            blob = encrypt_bytes_gcm(raw, key)
            _atomic_write(self.data_path, blob)


def _safe_float(s: str) -> float:
    try:
        return float((s or "").strip())
    except Exception:
        return 0.0


def dose_safety_level(med: Dict[str, Any], dose_mg: float, now_ts: float) -> Tuple[str, str]:
    interval_h = float(med.get("interval_hours") or 0.0)
    max_daily = float(med.get("max_daily_mg") or 0.0)
    history = list(med.get("history") or [])
    last_taken = float(med.get("last_taken_ts") or 0.0)

    mins_since = (now_ts - last_taken) / 60.0 if last_taken > 0 else 1e9

    cutoff = now_ts - 24 * 3600.0
    total_24h = 0.0
    for item in history:
        try:
            ts = float(item[0]); mg = float(item[1])
            if ts >= cutoff:
                total_24h += mg
        except Exception:
            continue

    projected = total_24h + max(0.0, float(dose_mg))
    ratio = (projected / max_daily) if max_daily > 0 else 0.0

    way_too_soon = (interval_h > 0) and (mins_since < interval_h * 60.0 * 0.60)
    too_soon = (interval_h > 0) and (mins_since < interval_h * 60.0 * 0.85)

    if way_too_soon or (max_daily > 0 and ratio >= 1.05):
        return "High", f"Unsafe: too soon or above daily max (24h~{projected:g} mg)."
    if too_soon or (max_daily > 0 and ratio >= 0.90):
        return "Medium", f"Caution: close to limits (24h~{projected:g} mg)."
    return "Low", f"OK: projected 24h total ~{projected:g} mg."


class MedSafeApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._exec: Optional[ThreadPoolExecutor] = None
        self._files_dir: Optional[Path] = None
        self._vault: Optional[Vault] = None
        self._selected_med_id: Optional[str] = None

    def build(self):
        self.title = "MedSafe"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Blue"

        self._exec = ThreadPoolExecutor(max_workers=1)

        if _kivy_platform == "android":
            self._files_dir = _android_files_dir() or Path(self.user_data_dir)
        else:
            self._files_dir = Path.home() / ".medsafe_files"
            self._files_dir.mkdir(parents=True, exist_ok=True)

        self._vault = Vault(self._files_dir)

        # Android runtime permission for notifications (Android 13+).
        # INTERNET is NOT runtime—must be in buildozer.spec.
        if _kivy_platform == "android":
            try:
                from android.permissions import request_permissions, Permission  # type: ignore
                request_permissions([Permission.POST_NOTIFICATIONS])
            except Exception:
                pass

        try:
            root = Builder.load_string(KV)
        except Exception as e:
            # If KV fails, you want to SEE it instead of silent crash.
            logger.exception("KV load failed: %s", e)
            raise

        Clock.schedule_once(lambda _dt: self.refresh_meds(), 0.1)
        return root

    def on_stop(self):
        try:
            if self._exec:
                self._exec.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    # ---- UI helpers ----
    def _set_status(self, text: str):
        try:
            self.root.ids.status.text = f"Status: {text}"
        except Exception:
            pass

    def _set_risk(self, lvl: str, msg: str = ""):
        try:
            self.root.ids.risk.text = f"Risk: {lvl}"
            if msg:
                self._set_status(msg)
        except Exception:
            pass

    def clear_risk(self):
        self._set_risk("—", "Ready")

    def show_debug(self):
        v = self._vault
        if not v:
            self._set_status("Debug: vault not ready")
            return
        self._set_status(f"Debug: data={v.data_path} exists={v.data_path.exists()}")

    # ---- Data refresh ----
    def refresh_meds(self):
        if not self._exec or not self._vault:
            return
        self._set_status("Loading…")
        fut = self._exec.submit(self._vault.load)
        fut.add_done_callback(lambda f: Clock.schedule_once(lambda _dt: self._refresh_ui_from_future(f), 0))

    def _refresh_ui_from_future(self, fut):
        try:
            data = fut.result()
        except Exception as e:
            logger.exception("Load failed: %s", e)
            data = {"version": 1, "meds": []}

        self._refresh_ui(data)

    def _refresh_ui(self, data: Dict[str, Any]):
        meds = list(data.get("meds") or [])

        try:
            lst = self.root.ids.med_list
            lst.clear_widgets()

            for med in meds:
                mid = str(med.get("id") or "")
                name = str(med.get("name") or "Medication")
                item = OneLineListItem(
                    text=name,
                    on_release=(lambda _x, _mid=mid: self.select_med(_mid)),
                )
                lst.add_widget(item)

            # keep selection valid
            if self._selected_med_id and not any(str(m.get("id")) == self._selected_med_id for m in meds):
                self._selected_med_id = None

            self._render_selected(data)
            self._set_status("Ready")
        except Exception as e:
            logger.exception("UI refresh failed: %s", e)
            self._set_status(f"UI refresh failed: {e}")

    def _render_selected(self, data: Dict[str, Any]):
        meds = list(data.get("meds") or [])
        sel = None
        if self._selected_med_id:
            for m in meds:
                if str(m.get("id") or "") == self._selected_med_id:
                    sel = m
                    break

        if not sel:
            self.root.ids.selected.text = "Selected: —"
            return

        self.root.ids.selected.text = f"Selected: {sel.get('name','—')}"
        self.root.ids.med_name.text = str(sel.get("name") or "")
        self.root.ids.dose_mg.text = str(sel.get("dose_mg") or "")
        self.root.ids.interval_h.text = str(sel.get("interval_hours") or "")
        self.root.ids.max_daily.text = str(sel.get("max_daily_mg") or "")

    def select_med(self, med_id: str):
        self._selected_med_id = med_id
        self.refresh_meds()

    # ---- CRUD ----
    def on_save_med(self):
        if not self._vault or not self._exec:
            return

        name = (self.root.ids.med_name.text or "").strip()
        dose = _safe_float(self.root.ids.dose_mg.text)
        interval_h = _safe_float(self.root.ids.interval_h.text)
        max_daily = _safe_float(self.root.ids.max_daily.text)

        if not name:
            self._set_status("Enter a medication name.")
            return

        current_selected = self._selected_med_id
        self._set_status("Saving…")

        def job(selected_id: Optional[str]):
            data = self._vault.load()
            meds = list(data.get("meds") or [])

            new_selected = selected_id

            if new_selected:
                for m in meds:
                    if str(m.get("id") or "") == new_selected:
                        m["name"] = name
                        m["dose_mg"] = dose
                        m["interval_hours"] = interval_h
                        m["max_daily_mg"] = max_daily
                        break
                else:
                    new_selected = None

            if not new_selected:
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
                new_selected = mid

            data["meds"] = meds
            self._vault.save(data)
            return new_selected

        fut = self._exec.submit(job, current_selected)
        fut.add_done_callback(lambda f: Clock.schedule_once(lambda _dt: self._save_done(f), 0))

    def _save_done(self, fut):
        try:
            new_selected = fut.result()
            self._selected_med_id = new_selected
            self._set_status("Saved.")
        except Exception as e:
            logger.exception("Save failed: %s", e)
            self._set_status(f"Save failed: {e}")
        self.refresh_meds()

    def on_delete_med(self):
        if not self._selected_med_id or not self._vault or not self._exec:
            self._set_status("Select a medication first.")
            return

        mid = self._selected_med_id
        self._set_status("Deleting…")

        def job(del_id: str):
            data = self._vault.load()
            meds = [m for m in (data.get("meds") or []) if str(m.get("id") or "") != del_id]
            data["meds"] = meds
            self._vault.save(data)
            return True

        fut = self._exec.submit(job, mid)
        fut.add_done_callback(lambda f: Clock.schedule_once(lambda _dt: self._delete_done(f), 0))

    def _delete_done(self, fut):
        try:
            fut.result()
            self._selected_med_id = None
            self._set_status("Deleted.")
        except Exception as e:
            logger.exception("Delete failed: %s", e)
            self._set_status(f"Delete failed: {e}")
        self.refresh_meds()

    def on_log_dose(self):
        if not self._selected_med_id or not self._vault or not self._exec:
            self._set_status("Select a medication first.")
            return

        sel_id = self._selected_med_id
        dose_override = _safe_float(self.root.ids.dose_mg.text)
        self._set_status("Checking…")

        def job(selected_id: str, override: float):
            data = self._vault.load()
            meds = list(data.get("meds") or [])
            now_ts = time.time()

            for m in meds:
                if str(m.get("id") or "") == selected_id:
                    dose_mg = float(override or m.get("dose_mg") or 0.0)
                    lvl, msg = dose_safety_level(m, dose_mg, now_ts)

                    hist = list(m.get("history") or [])
                    hist.append([now_ts, dose_mg])
                    m["history"] = hist[-300:]
                    m["last_taken_ts"] = now_ts
                    if override:
                        m["dose_mg"] = override

                    data["meds"] = meds
                    self._vault.save(data)
                    return (lvl, msg)

            return ("Medium", "Selection missing.")

        fut = self._exec.submit(job, sel_id, dose_override)
        fut.add_done_callback(lambda f: Clock.schedule_once(lambda _dt: self._log_done(f), 0))

    def _log_done(self, fut):
        try:
            lvl, msg = fut.result()
        except Exception as e:
            logger.exception("Log failed: %s", e)
            lvl, msg = ("High", f"Log failed: {e}")

        self._set_risk(lvl, msg)
        self.refresh_meds()


if __name__ == "__main__":
    MedSafeApp().run()

