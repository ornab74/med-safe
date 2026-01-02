# main.py
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import math
import os
import re
import sqlite3
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

import httpx

# Optional deps
try:
    import numpy as np  # type: ignore
except Exception as e:  # pragma: no cover
    np = None
    _NUMPY_IMPORT_ERR = e

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:  # pragma: no cover
    AESGCM = None

try:
    from textual import on  # type: ignore
    from textual.app import App, ComposeResult  # type: ignore
    from textual.containers import Container, Horizontal, Vertical  # type: ignore
    from textual.screen import Screen  # type: ignore
    from textual.widgets import (  # type: ignore
        Button,
        DataTable,
        Footer,
        Header,
        Input,
        Label,
        ListItem,
        ListView,
        Log,
        Markdown,
        Static,
        Switch,
    )
except Exception as e:  # pragma: no cover
    _TEXTUAL_IMPORT_ERR = e
    App = None  # type: ignore

MODEL_NAME = os.environ.get("ROADSCANNER_MODEL", "gpt-4.1")
OPENAI_RESPONSES_URL = os.environ.get("OPENAI_RESPONSES_URL", "https://api.openai.com/v1/responses")

HEX6 = re.compile(r"^#[0-9A-Fa-f]{6}$")

START = "#00FF00"
END = "#000000"
SENT = "#777777"
SPLIT = "#00AEEF"

IDX_START = 0
IDX_SPLIT = 14
IDX_BUDGET_START = 33
IDX_BUDGET_END = 35
IDX_SENT1 = 35
IDX_CHK_START = 36
IDX_CHK_END = 48
IDX_SENT2 = 48
IDX_END = 49


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def clamp01(x: float) -> float:
    return clamp(float(x), 0.0, 1.0)


def now_utc() -> int:
    return int(time.time())


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def b2_tag(b: bytes, n: int = 10) -> str:
    return hashlib.blake2s(b, digest_size=16).hexdigest()[:n]


def pbkdf2_key(passphrase: str, salt: bytes, length: int = 32, rounds: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, rounds, dklen=length)


def encrypt_blob(passphrase: str, plaintext: bytes, aad: bytes) -> Dict[str, bytes]:
    if AESGCM is None:
        raise RuntimeError("cryptography missing")
    salt = os.urandom(16)
    key = pbkdf2_key(passphrase, salt)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {"salt": salt, "nonce": nonce, "ct": ct}


def decrypt_blob(passphrase: str, salt: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    if AESGCM is None:
        raise RuntimeError("cryptography missing")
    key = pbkdf2_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, aad)


def resonance_required() -> bool:
    return bool(os.environ.get("RESONANCE_HASH", "").strip())


def resonance_check(phrase: Optional[str]) -> bool:
    expected = os.environ.get("RESONANCE_HASH", "").strip().lower()
    if not expected:
        return True
    if not phrase:
        return False
    got = sha256_hex(phrase.encode("utf-8")).lower()
    return got == expected


def rgb_to_hex(r: int, g: int, b: int) -> str:
    return "#{:02X}{:02X}{:02X}".format(r & 255, g & 255, b & 255)


def hex_to_rgb(hx: str) -> Tuple[int, int, int]:
    s = hx[1:] if hx.startswith("#") else hx
    return int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16)


def brightness(hx: str) -> float:
    r, g, b = hex_to_rgb(hx)
    return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255.0


def checksum_colors(payload: bytes, n: int = 12) -> List[str]:
    d1 = hashlib.sha256(payload).digest()
    d2 = hashlib.sha256(d1).digest()
    buf = d1 + d2
    out: List[str] = []
    for i in range(n):
        r, g, b = buf[i * 3 : (i + 1) * 3]
        out.append(rgb_to_hex(r, g, b))
    return out


def expected_checksum(tokens: List[str]) -> List[str]:
    pre = tokens[:IDX_CHK_START]
    return checksum_colors("|".join(pre).encode("utf-8"), 12)


def verify_beam(tokens: List[str], enforce_checksum: bool = True) -> Tuple[bool, str]:
    if not isinstance(tokens, list) or len(tokens) != 50:
        return False, "beam must be list len 50"
    if tokens[IDX_START] != START or tokens[IDX_END] != END:
        return False, "missing START/END"
    if tokens[IDX_SPLIT] != SPLIT:
        return False, "missing split marker"
    if tokens[IDX_SENT1] != SENT or tokens[IDX_SENT2] != SENT:
        return False, "missing sentinels"
    for t in tokens:
        if not isinstance(t, str) or not HEX6.match(t):
            return False, f"bad token {t!r}"
    if enforce_checksum and tokens[IDX_CHK_START:IDX_CHK_END] != expected_checksum(tokens):
        return False, "checksum mismatch"
    return True, "ok"


def fail_closed_beam() -> List[str]:
    dark = "#111111"
    toks = [START] + [dark] * 6 + [dark] + [dark] * 6 + [SPLIT] + [dark] * 16 + [dark] * 2 + [dark] * 2 + [SENT]
    toks += checksum_colors("|".join(toks).encode("utf-8"), 12)
    toks += [SENT, END]
    return toks


def beam_sig(tokens: List[str]) -> str:
    return b2_tag("|".join(tokens).encode("utf-8"), 10)


def budget_intensity(tokens: List[str]) -> float:
    ok, _ = verify_beam(tokens, enforce_checksum=False)
    if not ok:
        return 0.0
    chk = tokens[IDX_CHK_START:IDX_CHK_END]
    bud = tokens[IDX_BUDGET_START:IDX_BUDGET_END]
    return clamp(
        0.6 * (sum(brightness(x) for x in chk) / 12.0) + 0.4 * (sum(brightness(x) for x in bud) / 2.0),
        0.0,
        1.0,
    )


def halocline_seed_bytes(lat: float, lon: float, depth_m: float) -> bytes:
    lat_r = math.radians(lat)
    lon_r = math.radians(lon)
    d = float(depth_m)
    g1 = math.sin(lat_r) * math.cos(lon_r)
    g2 = math.cos(lat_r) * math.sin(lon_r * 0.7)
    g3 = math.tanh((d - 200.0) / 500.0)
    mix = f"QHALO:{lat:.6f},{lon:.6f},{d:.2f}|{g1:+.6f},{g2:+.6f},{g3:+.6f}"
    return hashlib.blake2s(mix.encode("utf-8"), digest_size=16).digest()


def qphase_tag(base: str, polymorph: bool, period_s: int) -> str:
    if not polymorph:
        return ""
    bucket = int(time.time()) // max(10, int(period_s))
    return b2_tag(
        hashlib.sha256(f"{base}|qbucket:{bucket}|pid:{os.getpid()}".encode("utf-8")).digest(),
        8,
    )


def det_u01(key: str) -> float:
    b = hashlib.blake2s(key.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(b, "big") / 2**64


def risk_color(r: float) -> str:
    r = clamp(float(r), 0.0, 1.0)
    hue = 120.0 * (1.0 - r)
    h = hue / 60.0
    i = int(h) % 6
    f = h - int(h)
    v, s = 1.0, 1.0
    p = v * (1 - s)
    q = v * (1 - s * f)
    t = v * (1 - s * (1 - f))
    if i == 0:
        rr, gg, bb = v, t, p
    elif i == 1:
        rr, gg, bb = q, v, p
    elif i == 2:
        rr, gg, bb = p, v, t
    elif i == 3:
        rr, gg, bb = p, q, v
    elif i == 4:
        rr, gg, bb = t, p, v
    else:
        rr, gg, bb = v, p, q
    return rgb_to_hex(int(rr * 255), int(gg * 255), int(bb * 255))


# ============================
# LIVE runtime pieces
# ============================

class RuntimeMode(str, Enum):
    SIMULATED = "simulated"
    LIVE = "live"


@dataclass
class LiveSensorFrame:
    """LIVE runtime observation for a single segment."""
    ts_utc: int
    segment_idx: int
    gps: Tuple[float, float]
    debris_detected: bool
    debris_severity: float   # 0..1
    visibility: float        # 0..1
    braking_entropy: float   # 0..1
    lateral_variance: float  # 0..1


def time_inflation_from_debris(severity: float) -> float:
    s = clamp01(severity)
    if s < 0.20:
        return 1.02
    if s < 0.40:
        return 1.10
    if s < 0.60:
        return 1.28
    if s < 0.80:
        return 1.55
    return 2.10


def predict_accident_probability(frame: LiveSensorFrame) -> Dict[str, float]:
    """Simple LIVE predictor."""
    base = (
        0.35 * clamp01(frame.debris_severity)
        + 0.25 * clamp01(frame.braking_entropy)
        + 0.20 * clamp01(frame.lateral_variance)
        + 0.20 * (1.0 - clamp01(frame.visibility))
    )
    base = clamp01(base)
    return {
        "p_2_min": clamp01(base * 0.60),
        "p_5_min": clamp01(base * 1.00),
        "p_10_min": clamp01(base * 1.40),
    }


def load_live_frames_jsonl(path: str) -> List[LiveSensorFrame]:
    """Loads JSONL frames."""
    p = (path or "").strip()
    if not p or not os.path.exists(p):
        return []
    out: List[LiveSensorFrame] = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
                gps = j.get("gps") or j.get("latlon") or j.get("pos")
                if isinstance(gps, (list, tuple)) and len(gps) == 2:
                    lat, lon = float(gps[0]), float(gps[1])
                else:
                    lat = float(j.get("lat"))
                    lon = float(j.get("lon"))
                out.append(
                    LiveSensorFrame(
                        ts_utc=int(j.get("ts_utc") or now_utc()),
                        segment_idx=int(j.get("segment_idx")),
                        gps=(lat, lon),
                        debris_detected=bool(j.get("debris_detected")),
                        debris_severity=float(j.get("debris_severity") or 0.0),
                        visibility=float(j.get("visibility") or 1.0),
                        braking_entropy=float(j.get("braking_entropy") or 0.0),
                        lateral_variance=float(j.get("lateral_variance") or 0.0),
                    )
                )
            except Exception:
                continue
    return out


def latest_frame_by_segment(frames: Sequence[LiveSensorFrame]) -> Dict[int, LiveSensorFrame]:
    best: Dict[int, LiveSensorFrame] = {}
    for fr in frames or []:
        k = int(fr.segment_idx)
        prev = best.get(k)
        if prev is None or int(fr.ts_utc) >= int(prev.ts_utc):
            best[k] = fr
    return best


# ============================
# LIVE FIR/IIR + IR telemetry pipeline
# ============================

@dataclass
class LiveFilterConfig:
    """Filtering config for LIVE frames."""
    fir_window: int = 5
    iir_alpha: float = 0.35
    blend_iir: float = 0.6
    spike_gain: float = 1.0


@dataclass
class _MetricState:
    win: deque
    ema: Optional[float] = None


@dataclass
class _SegmentFilterState:
    debris_severity: _MetricState
    visibility: _MetricState
    braking_entropy: _MetricState
    lateral_variance: _MetricState


@dataclass
class LiveTelemetryRecord:
    created_utc: int
    ts_utc: int
    segment_idx: int
    gps: Tuple[float, float]
    metric: str
    raw: float
    fir: float
    iir: float
    blended: float
    ir_spike: float


def _mean(xs: Sequence[float]) -> float:
    xs2 = list(xs)
    return (sum(xs2) / max(1, len(xs2))) if xs2 else 0.0


def _iir_update(prev: Optional[float], x: float, alpha: float) -> float:
    a = clamp(float(alpha), 0.0, 1.0)
    if prev is None:
        return float(x)
    return float(a * float(x) + (1.0 - a) * float(prev))


def _mk_metric_state(window: int) -> _MetricState:
    return _MetricState(win=deque(maxlen=max(1, int(window))), ema=None)


def _mk_segment_state(window: int) -> _SegmentFilterState:
    return _SegmentFilterState(
        debris_severity=_mk_metric_state(window),
        visibility=_mk_metric_state(window),
        braking_entropy=_mk_metric_state(window),
        lateral_variance=_mk_metric_state(window),
    )


def _filter_one(
    st: _MetricState,
    x_raw: float,
    cfg: LiveFilterConfig,
    metric_name: str,
    created_utc: int,
    fr: LiveSensorFrame,
) -> Tuple[float, LiveTelemetryRecord]:
    x = clamp01(x_raw)
    st.win.append(float(x))
    fir = clamp01(_mean(st.win))
    st.ema = _iir_update(st.ema, x, cfg.iir_alpha)
    iir = clamp01(st.ema if st.ema is not None else x)
    blend = clamp01(cfg.blend_iir) * iir + (1.0 - clamp01(cfg.blend_iir)) * fir

    ir_spike = clamp01(max(0.0, (x - iir) * float(cfg.spike_gain)))

    rec = LiveTelemetryRecord(
        created_utc=int(created_utc),
        ts_utc=int(fr.ts_utc),
        segment_idx=int(fr.segment_idx),
        gps=(float(fr.gps[0]), float(fr.gps[1])),
        metric=str(metric_name),
        raw=float(x),
        fir=float(fir),
        iir=float(iir),
        blended=float(blend),
        ir_spike=float(ir_spike),
    )
    return float(blend), rec


class LiveTelemetryPipeline:
    def __init__(self, cfg: Optional[LiveFilterConfig] = None) -> None:
        self.cfg = cfg or LiveFilterConfig()
        self._states: Dict[int, _SegmentFilterState] = {}

    def reset(self) -> None:
        self._states = {}

    def _seg_state(self, seg_idx: int) -> _SegmentFilterState:
        k = int(seg_idx)
        if k not in self._states:
            self._states[k] = _mk_segment_state(self.cfg.fir_window)
        return self._states[k]

    def ingest(self, frames: Sequence[LiveSensorFrame]) -> Tuple[List[LiveSensorFrame], List[LiveTelemetryRecord]]:
        out_frames: List[LiveSensorFrame] = []
        tel: List[LiveTelemetryRecord] = []
        created = now_utc()
        for fr in frames or []:
            st = self._seg_state(int(fr.segment_idx))
            debris_blend, rec_d = _filter_one(
                st.debris_severity, float(fr.debris_severity), self.cfg, "debris_severity", created, fr
            )
            vis_blend, rec_v = _filter_one(st.visibility, float(fr.visibility), self.cfg, "visibility", created, fr)
            br_blend, rec_b = _filter_one(
                st.braking_entropy, float(fr.braking_entropy), self.cfg, "braking_entropy", created, fr
            )
            lat_blend, rec_l = _filter_one(
                st.lateral_variance, float(fr.lateral_variance), self.cfg, "lateral_variance", created, fr
            )
            tel.extend([rec_d, rec_v, rec_b, rec_l])
            out_frames.append(
                LiveSensorFrame(
                    ts_utc=int(fr.ts_utc),
                    segment_idx=int(fr.segment_idx),
                    gps=(float(fr.gps[0]), float(fr.gps[1])),
                    debris_detected=bool(fr.debris_detected),
                    debris_severity=float(debris_blend),
                    visibility=float(vis_blend),
                    braking_entropy=float(br_blend),
                    lateral_variance=float(lat_blend),
                )
            )
        return out_frames, tel


def write_live_telemetry_jsonl(path: str, records: Sequence[LiveTelemetryRecord]) -> int:
    p = (path or "").strip()
    if not p:
        return 0
    try:
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        n = 0
        with open(p, "a", encoding="utf-8") as f:
            for r in records or []:
                f.write(
                    json.dumps(
                        {
                            "created_utc": r.created_utc,
                            "ts_utc": r.ts_utc,
                            "segment_idx": r.segment_idx,
                            "gps": [r.gps[0], r.gps[1]],
                            "metric": r.metric,
                            "raw": r.raw,
                            "fir": r.fir,
                            "iir": r.iir,
                            "blended": r.blended,
                            "ir_spike": r.ir_spike,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                n += 1
        return n
    except Exception:
        return 0


# ============================
# Roadmap helpers
# ============================

def _synthetic_road_name(city: str, i: int, u: float) -> str:
    """Deterministic, non-authoritative road naming."""
    city2 = (city or "city").replace("*", " ").title()
    families = [
        "Connector",
        "Bypass",
        "Parkway",
        "Boulevard",
        "Avenue",
        "Main St",
        "Industrial Rd",
        "River Rd",
        "Ridge Rd",
        "Loop",
    ]
    f = families[int(u * len(families)) % len(families)]
    direction = ["NB", "SB", "EB", "WB"][int((u * 10) % 4)]
    return f"{city2} {f} – Seg {i:02d} {direction}"


def _synthetic_segment_gps(lat: float, lon: float, i: int, base: str) -> Tuple[Tuple[float, float], Tuple[float, float]]:
    """Deterministic pseudo geometry around halocline point."""
    u0 = det_u01(f"{base}|gps|i:{i}|a")
    u1 = det_u01(f"{base}|gps|i:{i}|b")
    u2 = det_u01(f"{base}|gps|i:{i}|c")
    u3 = det_u01(f"{base}|gps|i:{i}|d")
    dlat0 = (u0 - 0.5) * 0.010
    dlon0 = (u1 - 0.5) * 0.010
    dlat1 = dlat0 + (u2 - 0.5) * 0.008
    dlon1 = dlon0 + (u3 - 0.5) * 0.008
    return (lat + dlat0, lon + dlon0), (lat + dlat1, lon + dlon1)


def load_roadmap(path: str) -> Dict[int, Dict[str, Any]]:
    """Optional mapping file for REAL road names + segment endpoints."""
    p = (path or "").strip()
    if not p or not os.path.exists(p):
        return {}
    try:
        j = json.loads(open(p, "r", encoding="utf-8").read())
        out: Dict[int, Dict[str, Any]] = {}
        if isinstance(j, dict):
            for k, v in j.items():
                try:
                    idx = int(k)
                except Exception:
                    continue
                if isinstance(v, dict):
                    out[idx] = v
        return out
    except Exception:
        return {}


# ============================
# Domain structures
# ============================

@dataclass
class Segment:
    idx: int
    name: str
    risk: float
    flow: float
    time: float
    risk_hex: str
    qphase: str

    # Road + geometry + LIVE overlays
    road: str = ""
    start_gps: Tuple[float, float] = (0.0, 0.0)
    end_gps: Tuple[float, float] = (0.0, 0.0)

    debris_detected: bool = False
    debris_gps: Optional[Tuple[float, float]] = None
    debris_severity: float = 0.0

    accident_p_2_min: float = 0.0
    accident_p_5_min: float = 0.0
    accident_p_10_min: float = 0.0
    live_ts_utc: int = 0


def simulate_segments(
    city: str,
    n: int,
    halocline: Tuple[float, float, float],
    beam: List[str],
    polymorph: bool,
    polymorph_period_s: int,
    quantum_mode: bool,
    runtime_mode: str = "simulated",
    live_frames: Optional[Sequence[LiveSensorFrame]] = None,
    roadmap: Optional[Dict[int, Dict[str, Any]]] = None,
) -> Tuple[List[Segment], Dict[str, Any]]:
    lat, lon, dep = halocline
    halo = halocline_seed_bytes(lat, lon, dep)
    halo_tag = b2_tag(halo, 8)
    sig = beam_sig(beam)
    base0 = f"{city}|{lat:.6f},{lon:.6f},{dep:.2f}|n:{n}|beam:{sig}|halo:{halo_tag}|qm:{int(quantum_mode)}"
    qph = qphase_tag(base0, polymorph, polymorph_period_s)
    bud = budget_intensity(beam)

    mode = (runtime_mode or "simulated").strip().lower()
    live_map = latest_frame_by_segment(list(live_frames or [])) if mode == RuntimeMode.LIVE.value else {}
    road_map = dict(roadmap or {})

    segs: List[Segment] = []
    for i in range(n):
        u = det_u01(f"{base0}|q:{qph}|i:{i}|u")
        v = det_u01(f"{base0}|q:{qph}|i:{i}|v")
        w = det_u01(f"{base0}|q:{qph}|i:{i}|w")

        qwarp = 0.0
        if quantum_mode:
            qwarp = 0.12 * abs(math.sin((i + 1) * (0.73 + 0.19 * w) + (u * 2.0 * math.pi)))

        risk = clamp(0.10 + 0.78 * abs((u - 0.5) * 2) + 0.08 * bud + qwarp, 0.0, 1.0)
        flow = clamp(1.0 - (0.58 * risk + 0.22 * abs(v - 0.5) + 0.20 * bud), 0.0, 1.0)
        t = clamp(
            1.0 + 1.6 * (1 - flow) + 0.8 * risk + 0.35 * bud + (0.25 * qwarp if quantum_mode else 0.0),
            0.8,
            5.0,
        )

        # Road + geometry
        rm = road_map.get(i)
        if isinstance(rm, dict):
            road = str(rm.get("road") or rm.get("name") or f"S{i:02d} ({city})")
            sg = rm.get("start_gps")
            eg = rm.get("end_gps")
            if isinstance(sg, (list, tuple)) and len(sg) == 2:
                start_gps = (float(sg[0]), float(sg[1]))
            else:
                start_gps = (lat, lon)
            if isinstance(eg, (list, tuple)) and len(eg) == 2:
                end_gps = (float(eg[0]), float(eg[1]))
            else:
                end_gps = (lat, lon)
        else:
            road = _synthetic_road_name(city, i, u)
            start_gps, end_gps = _synthetic_segment_gps(lat, lon, i, base0)

        debris_detected = False
        debris_gps: Optional[Tuple[float, float]] = None
        debris_sev = 0.0
        p2 = p5 = p10 = 0.0
        live_ts = 0

        # LIVE overlays
        if mode == RuntimeMode.LIVE.value and i in live_map:
            fr = live_map[i]
            live_ts = int(fr.ts_utc)
            debris_detected = bool(fr.debris_detected)
            debris_sev = clamp01(fr.debris_severity)
            if debris_detected:
                debris_gps = (float(fr.gps[0]), float(fr.gps[1]))
                infl = time_inflation_from_debris(debris_sev)
                t = clamp(t * infl, 0.8, 9.0)
                risk = clamp01(risk + 0.25 * debris_sev)

            probs = predict_accident_probability(fr)
            p2 = float(probs.get("p_2_min", 0.0))
            p5 = float(probs.get("p_5_min", 0.0))
            p10 = float(probs.get("p_10_min", 0.0))

        segs.append(
            Segment(
                idx=i,
                name=f"S{i:02d} ({city})",
                risk=float(risk),
                flow=float(flow),
                time=float(t),
                risk_hex=risk_color(risk),
                qphase=qph,
                road=str(road),
                start_gps=start_gps,
                end_gps=end_gps,
                debris_detected=bool(debris_detected),
                debris_gps=debris_gps,
                debris_severity=float(debris_sev),
                accident_p_2_min=float(p2),
                accident_p_5_min=float(p5),
                accident_p_10_min=float(p10),
                live_ts_utc=int(live_ts),
            )
        )

    meta = {
        "city": city,
        "n": n,
        "beam_sig": sig,
        "budget_intensity": bud,
        "halo_tag": halo_tag,
        "qphase": qph,
        "quantum_mode": bool(quantum_mode),
        "runtime_mode": mode,
        "live_frames": len(list(live_frames or [])),
        "ts": now_utc(),
    }
    return segs, meta


@dataclass
class Route:
    nodes: List[int]
    score: float
    time: float
    risk: float
    var: float
    robust: float
    tag: str
    explanation: str


def dissim(a: List[int], b: List[int]) -> float:
    sa, sb = set(a), set(b)
    return 1.0 - (len(sa & sb) / max(1, len(sa | sb)))


def plan_routes(
    city: str,
    segs: List[Segment],
    beam: List[str],
    top_k: int,
    polymorph: bool,
    polymorph_period_s: int,
    quantum_mode: bool,
) -> Tuple[List[Route], Dict[str, Any]]:
    n = len(segs)
    if n < 2:
        return [], {"error": "need >=2 segments"}
    sig = beam_sig(beam)
    bud = budget_intensity(beam)
    qref = segs[0].qphase if segs else ""
    base0 = f"route|{city}|n:{n}|beam:{sig}|bud:{bud:.4f}|qm:{int(quantum_mode)}|qref:{qref}"
    qph = qphase_tag(base0, polymorph, polymorph_period_s)

    start = int(det_u01(f"{base0}|q:{qph}|start") * n) % n
    goal = (start + 1 + int(det_u01(f"{base0}|q:{qph}|goal") * max(1, n - 1))) % n
    if goal == start:
        goal = (start + 1) % n

    candidates: List[List[int]] = []
    max_hops = min(10, max(4, n))
    for k in range(48):
        path = [start]
        cur = start
        hops = 0
        while cur != goal and hops < max_hops:
            step = 1 + int(det_u01(f"{base0}|q:{qph}|k:{k}|h:{hops}|step") * 3)
            if quantum_mode and det_u01(f"{base0}|q:{qph}|k:{k}|h:{hops}|jump") > 0.72:
                step += 1
            cur = (cur + step) % n
            if cur in path and len(path) > 2:
                cur = (cur + 1) % n
            path.append(cur)
            hops += 1
        if path[-1] == goal and len(path) >= 2:
            candidates.append(path)

    routes: List[Route] = []
    for path in candidates:
        rs = [segs[i].risk for i in path]
        ts = [segs[i].time for i in path]
        avg_r = sum(rs) / len(rs)
        var = sum((x - avg_r) ** 2 for x in rs) / len(rs)
        avg_t = sum(ts) / len(ts)
        robust = max(rs) - avg_r
        qbonus = 0.0
        if quantum_mode:
            qbonus = 0.15 * abs(math.sin(len(path) * 0.67 + bud * 2.1))
        score = 1.00 * avg_t + 1.10 * avg_r + 0.85 * var + 0.95 * robust + 0.55 * bud + qbonus
        tag = b2_tag(f"{qph}|{','.join(map(str, path))}".encode("utf-8"), 6)
        routes.append(Route(path, float(score), float(avg_t), float(avg_r), float(var), float(robust), tag, ""))

    routes.sort(key=lambda r: r.score)
    chosen: List[Route] = []
    min_d = 0.35 if n >= 8 else 0.25
    for r in routes:
        if not chosen or all(dissim(r.nodes, c.nodes) >= min_d for c in chosen):
            chosen.append(r)
        if len(chosen) >= max(1, int(top_k)):
            break
    chosen = chosen or routes[: max(1, int(top_k))]

    if chosen:
        best = chosen[0]
        worst = max(best.nodes, key=lambda i: segs[i].risk)
        best_flow = max(best.nodes, key=lambda i: segs[i].flow)
        best.explanation = (
            f"QPHASE: {qph}\n"
            f"START: {start}  GOAL: {goal}\n"
            f"BEAM_SIG: {sig}\n"
            f"BUDGET_INTENSITY: {bud:.3f}\n"
            f"BEST_FLOW: {segs[best_flow].name} flow={segs[best_flow].flow:.3f}\n"
            f"HIGHEST_RISK: {segs[worst].name} risk={segs[worst].risk:.3f}\n"
        )

    meta = {
        "city": city,
        "start": start,
        "goal": goal,
        "beam_sig": sig,
        "budget_intensity": bud,
        "qphase": qph,
        "quantum_mode": bool(quantum_mode),
        "routes_returned": len(chosen),
        "ts": now_utc(),
    }
    return chosen[: max(1, int(top_k))], meta


def beam_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "beam_tokens": {"type": "array", "minItems": 50, "maxItems": 50, "items": {"type": "string"}},
            "notes": {"type": "string"},
            "risk_hints": {"type": "object", "additionalProperties": True},
        },
        "required": ["beam_tokens", "notes", "risk_hints"],
    }


def extract_responses_text(j: Dict[str, Any]) -> str:
    ot = j.get("output_text")
    if isinstance(ot, str) and ot.strip():
        return ot.strip()

    out = j.get("output")
    if isinstance(out, list):
        chunks: List[str] = []
        for it in out:
            if not isinstance(it, dict):
                continue
            content = it.get("content")
            if not isinstance(content, list):
                continue
            for cc in content:
                if not isinstance(cc, dict):
                    continue
                if cc.get("type") in ("output_text", "text") and isinstance(cc.get("text"), str):
                    chunks.append(cc["text"])
        return "\n".join(x for x in chunks if x and x.strip()).strip()

    return ""


def build_beam_prompt(
    city: str,
    halocline: Tuple[float, float, float],
    segments: int,
    beams_local: int,
    polymorph: bool,
    quantum_mode: bool,
    seed_tag: str,
    real_world_inference: bool,
) -> Tuple[str, str]:
    rw = bool(real_world_inference)
    system = (
        "You are generating a synthetic \"ColorBeam\" for a simulation-only road-scanning system.\n"
        "Return JSON ONLY that matches the provided JSON Schema (no markdown, no commentary).\n"
        "\n"
        "HARD CONSTRAINTS (must follow exactly):\n"
        "- Output must be a JSON object with keys: beam_tokens, notes, risk_hints.\n"
        "- beam_tokens must be an array of exactly 50 strings.\n"
        "- Each token must match pattern '#RRGGBB' (6 hex digits).\n"
        "- Fixed indices:\n"
        "  * beam_tokens[0]  = '#00FF00'  (START)\n"
        "  * beam_tokens[14] = '#00AEEF'  (SPLIT)\n"
        "  * beam_tokens[35] = '#777777'  (SENTINEL)\n"
        "  * beam_tokens[36..47] reserved for checksum tokens (still '#RRGGBB')\n"
        "  * beam_tokens[48] = '#777777'  (SENTINEL)\n"
        "  * beam_tokens[49] = '#000000'  (END)\n"
        "\n"
        "SEMANTIC GOALS:\n"
        "- Indices 33..34 are budget tokens.\n"
        "- Prefer smooth gradients or clustered motifs.\n"
        "\n"
        "DETERMINISM REQUIREMENT:\n"
        "- Base all choices deterministically on SEED_TAG and index.\n"
        "\n"
        "CHECKSUM REGION POLICY (36..47):\n"
        "- Output valid placeholders if you cannot compute checksum.\n"
        "\n"
        "REAL-WORLD PRIORS (TEST-SIM ONLY):\n"
        f"- real_world_inference_enabled: {rw}\n"
        "- If enabled: you may use plausible priors but must frame them as assumptions.\n"
        "- Do NOT claim live sensing or real-time traffic.\n"
        "\n"
        "RISK_HINTS:\n"
        "- Include: seed_tag, city_key, halocline, modes, palette_intent, budget_strategy, zones.\n"
        "- If real_world_inference: include assumptions.\n"
        "\n"
        "NOTES: 3–8 sentences. No live claims.\n"
    )
    user = (
        "CONFIG:\n"
        f"- city_key: {city}\n"
        f"- halocline: {halocline[0]:.6f},{halocline[1]:.6f},{halocline[2]:.2f}\n"
        f"- segments: {int(segments)}\n"
        f"- local_beams: {int(beams_local)}\n"
        f"- polymorph_mode: {bool(polymorph)}\n"
        f"- quantum_mode: {bool(quantum_mode)}\n"
        f"- real_world_inference: {rw}\n"
        f"- SEED_TAG: {seed_tag}\n"
        "\nOUTPUT RULE: Return JSON only.\n"
    )
    return system, user


class OpenAIBeamClient:
    def __init__(self, api_key: str, timeout_s: float = 45.0) -> None:
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set.")
        self.api_key = api_key
        self.timeout_s = float(timeout_s)

    async def _post_responses(self, payload: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                r = await client.post(
                    OPENAI_RESPONSES_URL,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=payload,
                )
        except Exception as e:
            return None, f"request error: {type(e).__name__}: {e}"

        if r.status_code >= 400:
            try:
                j = r.json()
                msg = j.get("error", {}).get("message") or str(j.get("error") or "")
            except Exception:
                msg = r.text[:500]
            return None, f"HTTP {r.status_code}: {msg}"

        try:
            return r.json(), None
        except Exception as e:
            return None, f"bad JSON response: {type(e).__name__}: {e}"

    async def generate_beam(
        self,
        city: str,
        halocline: Tuple[float, float, float],
        segments: int,
        beams_local: int,
        polymorph: bool,
        quantum_mode: bool,
        real_world_inference: bool = False,
    ) -> Tuple[List[str], Dict[str, Any]]:
        halo = halocline_seed_bytes(halocline[0], halocline[1], halocline[2])
        halo_tag = b2_tag(halo, 8)
        seed_tag = sha256_hex(
            f"{city}|{halocline}|{segments}|{beams_local}|{polymorph}|qm:{int(quantum_mode)}|rwi:{int(bool(real_world_inference))}|halo:{halo_tag}".encode(
                "utf-8"
            )
        )[:32]

        system, user = build_beam_prompt(
            city, halocline, segments, beams_local, polymorph, quantum_mode, seed_tag, bool(real_world_inference)
        )
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

        audit: Dict[str, Any] = {
            "model": MODEL_NAME,
            "seed_tag": seed_tag,
            "halo_tag": halo_tag,
            "real_world_inference": bool(real_world_inference),
            "ts": now_utc(),
        }

        attempts: List[Tuple[str, Dict[str, Any]]] = [
            (
                "responses_schema",
                {
                    "model": MODEL_NAME,
                    "input": messages,
                    "max_output_tokens": 1200,
                    "temperature": 0.0,
                    "text": {
                        "format": {"type": "json_schema", "name": "beam_50", "schema": beam_schema(), "strict": True}
                    },
                },
            ),
            (
                "responses_object",
                {
                    "model": MODEL_NAME,
                    "input": messages,
                    "max_output_tokens": 1200,
                    "temperature": 0.0,
                    "text": {"format": {"type": "json_object"}},
                },
            ),
            ("responses_plain", {"model": MODEL_NAME, "input": messages, "max_output_tokens": 1200, "temperature": 0.0}),
        ]

        resp_json: Optional[Dict[str, Any]] = None
        mode_used: Optional[str] = None
        last_err: Optional[str] = None

        for mode, payload in attempts:
            j, err = await self._post_responses(payload)
            if j is not None:
                resp_json = j
                mode_used = mode
                break
            last_err = f"{mode}: {err}"

        audit["mode_used"] = mode_used

        if resp_json is None:
            audit["llm_ok"] = False
            audit["llm_error"] = last_err or "unknown error"
            beam = fail_closed_beam()
            audit["beam_ok"], audit["beam_msg"] = verify_beam(beam, enforce_checksum=True)
            audit["beam_sig"] = beam_sig(beam)
            return beam, audit

        text = extract_responses_text(resp_json)
        if not text:
            audit["llm_ok"] = False
            audit["llm_error"] = "empty output"
            beam = fail_closed_beam()
            audit["beam_ok"], audit["beam_msg"] = verify_beam(beam, enforce_checksum=True)
            audit["beam_sig"] = beam_sig(beam)
            return beam, audit

        try:
            obj = json.loads(text)
        except Exception:
            audit["llm_ok"] = False
            audit["llm_error"] = "invalid JSON"
            beam = fail_closed_beam()
            audit["beam_ok"], audit["beam_msg"] = verify_beam(beam, enforce_checksum=True)
            audit["beam_sig"] = beam_sig(beam)
            return beam, audit

        tokens = obj.get("beam_tokens")
        audit["llm_ok"] = True

        if not isinstance(tokens, list):
            audit["beam_ok"] = False
            audit["beam_msg"] = "beam_tokens missing/not list"
            beam = fail_closed_beam()
            audit["beam_sig"] = beam_sig(beam)
            return beam, audit

        toks = [t.strip() if isinstance(t, str) else "" for t in tokens]
        ok_struct, msg = verify_beam(toks, enforce_checksum=False)
        if not ok_struct:
            audit["beam_ok"] = False
            audit["beam_msg"] = msg
            beam = fail_closed_beam()
            audit["beam_sig"] = beam_sig(beam)
            return beam, audit

        exp = expected_checksum(toks)
        original_chk = toks[IDX_CHK_START:IDX_CHK_END]
        if original_chk != exp:
            toks[IDX_CHK_START:IDX_CHK_END] = exp
            audit["checksum_fixed"] = True
            audit["checksum_original"] = original_chk
            audit["checksum_expected"] = exp

        ok, msg2 = verify_beam(toks, enforce_checksum=True)
        audit["beam_ok"] = ok
        audit["beam_msg"] = msg2
        audit["beam_sig"] = beam_sig(toks if ok else fail_closed_beam())
        return (toks if ok else fail_closed_beam()), audit


def build_guidance_prompt(
    city: str,
    halocline: Tuple[float, float, float],
    beam: List[str],
    segs: List[Segment],
    route: Route,
    quantum_mode: bool,
    real_world_inference: bool,
    runtime_mode: str = "simulated",
) -> Tuple[str, str]:
    worst = max(route.nodes, key=lambda i: segs[i].risk) if route.nodes else 0
    best = max(route.nodes, key=lambda i: segs[i].flow) if route.nodes else 0
    rw = bool(real_world_inference)
    mode = (runtime_mode or "simulated").strip().lower()

    if mode == RuntimeMode.LIVE.value:
        system = (
            "You are a real-time roadway safety intelligence system.\n"
            "You have access to LIVE roadway sensing and active hazard detection streams.\n"
            "Write decision-ready route guidance in Markdown.\n"
            "\nHARD RULES:\n"
            "- Use ONLY the numeric metrics and segment list provided.\n"
            "- Treat debris, GPS hazard positions, and accident probabilities as LIVE observations/predictions.\n"
            "- Clearly distinguish observed hazards vs forecasted risk.\n"
            "- If forecasts escalate, prioritize safety over speed.\n"
            "\nOUTPUT FORMAT:\n"
            "## Overview\n"
            "## Live Hazard Assessment\n"
            "## Decision Profile\n"
            "## Tradeoffs & Rationale (10–16 bullets)\n"
            "## Segment Drilldown\n"
            "## Mitigation Moves\n"
            "## Quantum\n"
            "## What Would Change This Recommendation?\n"
        )
    else:
        system = (
            "You are an operator assistant for a simulation-only road scanning system.\n"
            "Write advanced, decision-ready route guidance in Markdown.\n"
            "\nHARD RULES:\n"
            "- Use ONLY the numeric metrics and segment list provided.\n"
            "- Do NOT claim live sensing, real-time traffic, or actual incidents.\n"
            "- If you mention real-world patterns, present them ONLY as hypothetical priors.\n"
            f"\nREAL-WORLD INFERENCE MODE (test-sim priors): {rw}\n"
            "\nOUTPUT FORMAT:\n"
            "## Overview\n"
            "## Decision Profile\n"
            "## Tradeoffs & Rationale (10–16 bullets)\n"
            + ("## Assumptions (Test Sim)\n" if rw else "")
            + "## Segment Drilldown\n"
            "## Mitigation Moves\n"
            "## Quantum\n"
            "## What Would Change This Recommendation?\n"
        )

    seg_jsonl = "\n".join(
        json.dumps(
            {
                "idx": s.idx,
                "name": s.name,
                "road": s.road,
                "start_gps": [round(float(s.start_gps[0]), 6), round(float(s.start_gps[1]), 6)],
                "end_gps": [round(float(s.end_gps[0]), 6), round(float(s.end_gps[1]), 6)],
                "risk": round(float(s.risk), 6),
                "flow": round(float(s.flow), 6),
                "time": round(float(s.time), 6),
                "risk_hex": s.risk_hex,
                "qphase": s.qphase,
                "live_ts_utc": int(s.live_ts_utc),
                "debris_detected": bool(s.debris_detected),
                "debris_gps": (
                    [round(float(s.debris_gps[0]), 6), round(float(s.debris_gps[1]), 6)] if s.debris_gps else None
                ),
                "debris_severity": round(float(s.debris_severity), 6),
                "accident_p_2_min": round(float(s.accident_p_2_min), 6),
                "accident_p_5_min": round(float(s.accident_p_5_min), 6),
                "accident_p_10_min": round(float(s.accident_p_10_min), 6),
            },
            ensure_ascii=False,
        )
        for s in (segs or [])
    )

    user = (
        "METRICS INPUTS:\n"
        f"- city_key: {city}\n"
        f"- halocline: {halocline[0]:.6f},{halocline[1]:.6f},{halocline[2]:.2f}\n"
        f"- beam_signature: {beam_sig(beam)}\n"
        f"- budget_intensity: {budget_intensity(beam):.3f}\n"
        f"- runtime_mode: {mode}\n"
        f"- real_world_inference: {rw}\n"
        f"- route_path: {' -> '.join(str(x) for x in route.nodes)}\n"
        f"- score: {route.score:.3f}\n"
        f"- time: {route.time:.3f}\n"
        f"- risk: {route.risk:.3f}\n"
        f"- variance: {route.var:.4f}\n"
        f"- robustness: {route.robust:.3f}\n"
        f"- highest_risk_segment: {segs[worst].name} (risk={segs[worst].risk:.3f})\n"
        f"- best_flow_segment: {segs[best].name} (flow={segs[best].flow:.3f})\n"
        f"- qphase: {segs[0].qphase if segs else ''}\n"
        f"- quantum_mode: {bool(quantum_mode)}\n"
        "\nSEGMENTS (JSONL):\n"
        + (seg_jsonl + "\n" if seg_jsonl else "(none)\n")
    )
    return system, user


class OpenAIGuidanceClient:
    def __init__(self, api_key: str, timeout_s: float = 45.0) -> None:
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set.")
        self.api_key = api_key
        self.timeout_s = float(timeout_s)

    async def generate(
        self,
        city: str,
        halocline: Tuple[float, float, float],
        beam: List[str],
        segs: List[Segment],
        route: Route,
        quantum_mode: bool,
        real_world_inference: bool,
        runtime_mode: str = "simulated",
    ) -> Tuple[str, Dict[str, Any]]:
        system, user = build_guidance_prompt(
            city,
            halocline,
            beam,
            segs,
            route,
            quantum_mode,
            bool(real_world_inference),
            runtime_mode=runtime_mode,
        )
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        audit: Dict[str, Any] = {
            "model": MODEL_NAME,
            "real_world_inference": bool(real_world_inference),
            "runtime_mode": (runtime_mode or "simulated").strip().lower(),
            "ts": now_utc(),
        }

        payload = {"model": MODEL_NAME, "input": messages, "max_output_tokens": 1400, "temperature": 0.25}
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                r = await client.post(
                    OPENAI_RESPONSES_URL,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=payload,
                )
        except Exception as e:
            audit["ok"] = False
            audit["error"] = f"{type(e).__name__}: {e}"
            return "", audit

        if r.status_code >= 400:
            try:
                j = r.json()
                msg = j.get("error", {}).get("message") or str(j.get("error") or "")
            except Exception:
                msg = r.text[:500]
            audit["ok"] = False
            audit["error"] = f"HTTP {r.status_code}: {msg}"
            return "", audit

        try:
            j = r.json()
        except Exception as e:
            audit["ok"] = False
            audit["error"] = f"bad JSON response: {type(e).__name__}: {e}"
            return "", audit

        text = extract_responses_text(j)
        if not text:
            audit["ok"] = False
            audit["error"] = "empty output"
            return "", audit

        audit["ok"] = True
        return text.strip(), audit


class VaultDB:
    def __init__(self, path: str = "quantum_roadscanner.sqlite") -> None:
        self.path = path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA foreign_keys=ON;")
        return con

    def _init(self) -> None:
        con = self._conn()
        try:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS beams (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_utc INTEGER NOT NULL,
                    city TEXT NOT NULL,
                    halocline TEXT NOT NULL,
                    model TEXT NOT NULL,
                    beam_sig TEXT NOT NULL,
                    beam_ok INTEGER NOT NULL,
                    enc INTEGER NOT NULL,
                    aad TEXT NOT NULL,
                    salt BLOB,
                    nonce BLOB,
                    ciphertext BLOB,
                    plaintext_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_beams_city ON beams(city);
                """
            )
            con.commit()
        finally:
            con.close()

    def put_beam(self, city: str, halocline: str, model: str, beam: List[str], audit: Dict[str, Any]) -> int:
        created = now_utc()
        sig = beam_sig(beam)
        ok, _ = verify_beam(beam, enforce_checksum=True)
        payload = {"beam_tokens": beam, "audit": audit}
        plaintext = json.dumps(payload, ensure_ascii=False)
        aad_obj = {"kind": "beam", "created_utc": created, "city": city, "beam_sig": sig}
        aad = json.dumps(aad_obj, sort_keys=True)
        passphrase = os.environ.get("VAULT_PASSPHRASE", "") or ""
        enc_ok = False
        salt = nonce = ct = None
        pt = plaintext
        if passphrase and AESGCM is not None:
            try:
                enc = encrypt_blob(passphrase, plaintext.encode("utf-8"), aad.encode("utf-8"))
                salt, nonce, ct = enc["salt"], enc["nonce"], enc["ct"]
                pt = None
                enc_ok = True
            except Exception:
                enc_ok = False

        con = self._conn()
        try:
            cur = con.cursor()
            cur.execute(
                """
                INSERT INTO beams (created_utc, city, halocline, model, beam_sig, beam_ok, enc, aad, salt, nonce, ciphertext, plaintext_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created,
                    city,
                    halocline,
                    model,
                    sig,
                    1 if ok else 0,
                    1 if enc_ok else 0,
                    aad,
                    sqlite3.Binary(salt) if salt is not None else None,
                    sqlite3.Binary(nonce) if nonce is not None else None,
                    sqlite3.Binary(ct) if ct is not None else None,
                    pt,
                ),
            )
            con.commit()
            return int(cur.lastrowid)
        finally:
            con.close()

    def list_beams(self, limit: int = 50) -> List[Tuple[int, int, str, str, str, int, int]]:
        con = self._conn()
        try:
            cur = con.cursor()
            cur.execute(
                """
                SELECT id, created_utc, city, halocline, beam_sig, beam_ok, enc
                FROM beams ORDER BY id DESC LIMIT ?
                """,
                (int(limit),),
            )
            return [
                (int(r[0]), int(r[1]), str(r[2]), str(r[3]), str(r[4]), int(r[5]), int(r[6])) for r in cur.fetchall()
            ]
        finally:
            con.close()

    def load_beam(self, beam_id: int, resonance_phrase: Optional[str]) -> Dict[str, Any]:
        con = self._conn()
        try:
            cur = con.cursor()
            cur.execute("SELECT enc, aad, salt, nonce, ciphertext, plaintext_json FROM beams WHERE id=?", (int(beam_id),))
            row = cur.fetchone()
        finally:
            con.close()
        if not row:
            raise KeyError("beam not found")
        enc, aad, salt, nonce, ct, pt = int(row[0]), str(row[1]), row[2], row[3], row[4], row[5]
        if enc == 1:
            if resonance_required() and not resonance_check(resonance_phrase):
                raise PermissionError("resonance gate failed")
            passphrase = os.environ.get("VAULT_PASSPHRASE", "") or ""
            if not passphrase:
                raise PermissionError("VAULT_PASSPHRASE not set")
            if AESGCM is None:
                raise RuntimeError("cryptography missing")
            if not (salt and nonce and ct):
                raise RuntimeError("encrypted record missing fields")
            plaintext = decrypt_blob(passphrase, salt, nonce, ct, aad.encode("utf-8"))
            return json.loads(plaintext.decode("utf-8"))
        if pt is None:
            raise RuntimeError("missing payload")
        return json.loads(str(pt))


def beam_md(beam: List[str], audit: Dict[str, Any]) -> str:
    ok1, msg1 = verify_beam(beam, enforce_checksum=False)
    ok2, msg2 = verify_beam(beam, enforce_checksum=True)
    chk = beam[IDX_CHK_START:IDX_CHK_END] if len(beam) == 50 else []
    bud = beam[IDX_BUDGET_START:IDX_BUDGET_END] if len(beam) == 50 else []
    prev = beam[:10] if beam else []
    md = [
        "# Beam",
        f"- valid(struct): `{ok1}` · `{msg1}`",
        f"- valid(checksum): `{ok2}` · `{msg2}`",
        f"- signature: `{beam_sig(beam) if ok1 else 'invalid'}`",
        f"- budget_intensity: `{budget_intensity(beam) if ok1 else 0.0:.3f}`",
        f"- mode_used: `{audit.get('mode_used')}`",
        f"- llm_ok: `{audit.get('llm_ok')}`",
        f"- llm_error: `{audit.get('llm_error')}`",
        f"- preview: `{', '.join(prev)}`",
        f"- budget_tokens: `{', '.join(bud)}`",
        f"- checksum: `{', '.join(chk)}`",
        f"- real_world_inference: `{bool(audit.get('real_world_inference'))}`",
    ]
    return "\n".join(md)


def routes_md(routes: List[Route]) -> str:
    if not routes:
        return "# Routes\n\nNo routes planned yet."
    out = ["# Routes", ""]
    for i, r in enumerate(routes[:8]):
        out.append(
            f"**{i+1}.** score=`{r.score:.3f}` time=`{r.time:.3f}` risk=`{r.risk:.3f}` var=`{r.var:.4f}` robust=`{r.robust:.3f}` tag=`{r.tag}`"
        )
        out.append(f"- path: `{ ' → '.join(map(str, r.nodes)) }`")
        out.append("")
    return "\n".join(out)


# ============================
# Quantum-ish QRAG (numpy only)
# ============================

def _np_required() -> None:
    if np is None:
        raise RuntimeError(f"numpy not available: {_NUMPY_IMPORT_ERR}")


def _normalize(v: Any, eps: float = 1e-12) -> Any:
    _np_required()
    x = np.asarray(v, dtype=np.float64)
    n = float(np.linalg.norm(x))
    if n < eps:
        return x
    return x / n


def _cosine(a: Any, b: Any) -> float:
    _np_required()
    aa = _normalize(a)
    bb = _normalize(b)
    return float(np.dot(aa, bb))


def _rgb_bucket(v: int, levels: int) -> int:
    v = int(max(0, min(255, v)))
    if levels <= 1:
        return 0
    return int((v * levels) // 256)


def _axis_for_wire(wire: int, n: int) -> int:
    return (n - 1) - int(wire)


def _apply_1local(state: Any, gate: Any, wire: int, n: int, d: int) -> Any:
    _np_required()
    ax = _axis_for_wire(wire, n)
    tens = np.asarray(state).reshape([d] * n)
    tens = np.moveaxis(tens, ax, 0)
    tens = (gate @ tens.reshape(d, -1)).reshape([d] + [d] * (n - 1))
    tens = np.moveaxis(tens, 0, ax)
    return tens.reshape(-1)


def _apply_2local(state: Any, gate: Any, w0: int, w1: int, n: int, d: int) -> Any:
    _np_required()
    a0 = _axis_for_wire(w0, n)
    a1 = _axis_for_wire(w1, n)
    if a0 == a1:
        raise ValueError("distinct wires required")
    tens = np.asarray(state).reshape([d] * n)
    tens = np.moveaxis(tens, [a0, a1], [0, 1])
    tens2 = tens.reshape(d * d, -1)
    tens2 = (gate @ tens2).reshape([d, d] + [d] * (n - 2))
    tens2 = np.moveaxis(tens2, [0, 1], [a0, a1])
    return tens2.reshape(-1)


def _basis_state_qubits(bits_by_wire: Sequence[int], n: int) -> Any:
    _np_required()
    idx = 0
    for w, b in enumerate(bits_by_wire):
        if int(b) & 1:
            idx |= (1 << int(w))
    v = np.zeros((1 << n,), dtype=np.complex128)
    v[idx] = 1.0 + 0j
    return v


def _basis_state_qutrits(levels_by_wire: Sequence[int], n: int) -> Any:
    _np_required()
    idx = 0
    for w, lv in enumerate(levels_by_wire):
        idx += int(lv) * (3 ** int(w))
    v = np.zeros((3 ** n,), dtype=np.complex128)
    v[idx] = 1.0 + 0j
    return v


def _rx(theta: float) -> Any:
    _np_required()
    t = float(theta) / 2.0
    c = math.cos(t)
    s = math.sin(t)
    return np.array([[c, -1j * s], [-1j * s, c]], dtype=np.complex128)


def _ry(theta: float) -> Any:
    _np_required()
    t = float(theta) / 2.0
    c = math.cos(t)
    s = math.sin(t)
    return np.array([[c, -s], [s, c]], dtype=np.complex128)


def _apply_cnot(state: Any, control: int, target: int, n: int) -> Any:
    _np_required()
    st = np.asarray(state, dtype=np.complex128).copy()
    cbit = 1 << int(control)
    tbit = 1 << int(target)
    for i in range(st.size):
        if (i & cbit) and not (i & tbit):
            j = i | tbit
            st[i], st[j] = st[j], st[i]
    return st


def _apply_cz(state: Any, w0: int, w1: int, n: int) -> Any:
    _np_required()
    st = np.asarray(state, dtype=np.complex128).copy()
    b0 = 1 << int(w0)
    b1 = 1 << int(w1)
    for i in range(st.size):
        if (i & b0) and (i & b1):
            st[i] *= -1.0
    return st


def _trx_qutrit(theta: float) -> Any:
    _np_required()
    t = float(theta) / 2.0
    c = math.cos(t)
    s = math.sin(t)
    u = np.eye(3, dtype=np.complex128)
    u[0, 0] = c
    u[1, 1] = c
    u[0, 1] = -1j * s
    u[1, 0] = -1j * s
    return u


def _try_qutrit(theta: float) -> Any:
    _np_required()
    t = float(theta) / 2.0
    c = math.cos(t)
    s = math.sin(t)
    u = np.eye(3, dtype=np.complex128)
    u[1, 1] = c
    u[2, 2] = c
    u[1, 2] = -s
    u[2, 1] = s
    return u


@dataclass
class QuantumRGBConfig:
    levels_per_channel: int = 3
    depth: int = 2
    shots: int = 0
    seed: int = 7
    prefer_qutrit: bool = True


@dataclass
class QuantumRAGConfig:
    db_path: str = "quantum_rgb_rag.sqlite"
    table: str = "items"


@dataclass
class LLMConfig:
    api_key_env: str = "OPENAI_API_KEY"
    model: str = "gpt-4.1"
    endpoint: str = OPENAI_RESPONSES_URL
    timeout_s: float = 45.0


class QuantumRGBEmbedder:
    """Tiny numpy statevector embedder."""
    def __init__(self, qcfg: QuantumRGBConfig) -> None:
        _np_required()
        self.qcfg = qcfg
        self._rng = np.random.default_rng(int(qcfg.seed))
        self._use_qutrit = False
        self._dim: Optional[int] = None
        self._thetas_qutrit: Optional[Any] = None
        self._thetas_qubit: Optional[Any] = None
        self._build()

    @property
    def uses_qutrit(self) -> bool:
        return self._use_qutrit

    @property
    def embedding_dim(self) -> int:
        if self._dim is None:
            raise RuntimeError("embedder not initialized")
        return int(self._dim)

    def _qutrit_color_unitary(self, theta: float) -> Any:
        _np_required()
        t = float(theta)
        c = math.cos(t)
        s = math.sin(t)
        u = np.eye(9, dtype=np.complex128)
        i01 = 0 * 3 + 1
        i10 = 1 * 3 + 0
        i12 = 1 * 3 + 2
        i21 = 2 * 3 + 1
        u[[i01, i10], [i01, i10]] = c
        u[i01, i10] = 1j * s
        u[i10, i01] = 1j * s
        u[[i12, i21], [i12, i21]] = c
        u[i12, i21] = -1j * s
        u[i21, i12] = -1j * s
        phase = np.exp(1j * 0.35 * t)
        u[8, 8] = phase
        return u

    def _try_build_qutrit(self) -> bool:
        if not bool(self.qcfg.prefer_qutrit):
            return False
        depth = int(max(0, self.qcfg.depth))
        self._thetas_qutrit = self._rng.normal(0.0, 0.15, size=(depth, 6)).astype(np.float64)
        self._use_qutrit = True
        self._dim = 27
        return True

    def _try_build_qubit(self) -> bool:
        depth = int(max(0, self.qcfg.depth))
        self._thetas_qubit = self._rng.normal(0.0, 0.15, size=(depth, 12)).astype(np.float64)
        self._use_qutrit = False
        self._dim = 64
        return True

    def _build(self) -> None:
        if self._try_build_qutrit():
            return
        self._try_build_qubit()

    def _simulate_qutrit_probs(self, rgb_state: Sequence[int]) -> Any:
        _np_required()
        depth = int(max(0, self.qcfg.depth))
        thetas = (
            np.asarray(self._thetas_qutrit, dtype=np.float64)
            if self._thetas_qutrit is not None
            else np.zeros((0, 6), dtype=np.float64)
        )

        s0, s1, s2 = [int(rgb_state[0]), int(rgb_state[1]), int(rgb_state[2])]
        s0 = int(max(0, min(2, s0)))
        s1 = int(max(0, min(2, s1)))
        s2 = int(max(0, min(2, s2)))
        st = _basis_state_qutrits([s0, s1, s2], n=3)

        for d in range(depth):
            a0, b0, a1, b1, a2, b2 = [float(x) for x in thetas[d]]
            st = _apply_1local(st, _trx_qutrit(a0), wire=0, n=3, d=3)
            st = _apply_1local(st, _try_qutrit(b0), wire=0, n=3, d=3)
            st = _apply_1local(st, _trx_qutrit(a1), wire=1, n=3, d=3)
            st = _apply_1local(st, _try_qutrit(b1), wire=1, n=3, d=3)
            st = _apply_1local(st, _trx_qutrit(a2), wire=2, n=3, d=3)
            st = _apply_1local(st, _try_qutrit(b2), wire=2, n=3, d=3)

            e01 = self._qutrit_color_unitary(a0 + b1 + 0.13 * d)
            e12 = self._qutrit_color_unitary(a1 + b2 + 0.11 * d)
            st = _apply_2local(st, e01, w0=0, w1=1, n=3, d=3)
            st = _apply_2local(st, e12, w0=1, w1=2, n=3, d=3)

        probs = (np.abs(st) ** 2).astype(np.float64)
        probs = probs / max(1e-18, float(np.sum(probs)))
        shots = int(self.qcfg.shots or 0)
        if shots > 0:
            counts = self._rng.multinomial(shots, probs)
            probs = counts.astype(np.float64) / float(shots)
        return probs

    def _simulate_qubit_probs(self, rgb_state: Sequence[int]) -> Any:
        _np_required()
        depth = int(max(0, self.qcfg.depth))
        thetas = (
            np.asarray(self._thetas_qubit, dtype=np.float64)
            if self._thetas_qubit is not None
            else np.zeros((0, 12), dtype=np.float64)
        )

        r = int(max(0, min(3, int(rgb_state[0]))))
        g = int(max(0, min(3, int(rgb_state[1]))))
        b = int(max(0, min(3, int(rgb_state[2]))))

        bits = [0] * 6
        bits[0] = (r >> 1) & 1
        bits[1] = r & 1
        bits[2] = (g >> 1) & 1
        bits[3] = g & 1
        bits[4] = (b >> 1) & 1
        bits[5] = b & 1

        st = _basis_state_qubits(bits, n=6)

        for d in range(depth):
            row = [float(x) for x in thetas[d]]
            for w in range(6):
                st = _apply_1local(st, _rx(row[2 * w]), wire=w, n=6, d=2)
                st = _apply_1local(st, _ry(row[2 * w + 1]), wire=w, n=6, d=2)

            st = _apply_cnot(st, control=0, target=2, n=6)
            st = _apply_cnot(st, control=2, target=4, n=6)
            st = _apply_cnot(st, control=1, target=3, n=6)
            st = _apply_cnot(st, control=3, target=5, n=6)

            st = _apply_cz(st, w0=0, w1=1, n=6)
            st = _apply_cz(st, w0=2, w1=3, n=6)
            st = _apply_cz(st, w0=4, w1=5, n=6)

        probs = (np.abs(st) ** 2).astype(np.float64)
        probs = probs / max(1e-18, float(np.sum(probs)))
        shots = int(self.qcfg.shots or 0)
        if shots > 0:
            counts = self._rng.multinomial(shots, probs)
            probs = counts.astype(np.float64) / float(shots)
        return probs

    def embed_rgb(self, r: int, g: int, b: int) -> Any:
        levels = int(self.qcfg.levels_per_channel)
        if self._use_qutrit:
            s = [_rgb_bucket(int(r), levels), _rgb_bucket(int(g), levels), _rgb_bucket(int(b), levels)]
            s = [int(max(0, min(2, x))) for x in s]
            probs = self._simulate_qutrit_probs(s)
        else:
            s = [_rgb_bucket(int(r), 4), _rgb_bucket(int(g), 4), _rgb_bucket(int(b), 4)]
            probs = self._simulate_qubit_probs(s)
        return _normalize(np.asarray(probs, dtype=np.float64))

    def embed_hex(self, hx: str) -> Any:
        rr, gg, bb = hex_to_rgb(hx)
        return self.embed_rgb(rr, gg, bb)

    def embed_colorbeam(self, beam_tokens: Sequence[str]) -> Any:
        _np_required()
        vs: List[Any] = []
        for t in beam_tokens:
            if isinstance(t, str) and HEX6.match(t):
                vs.append(self.embed_hex(t))
        if not vs:
            return np.zeros((self.embedding_dim,), dtype=np.float64)
        m = np.mean(np.stack(vs, axis=0), axis=0)
        return _normalize(m)


class QuantumRAGStore:
    def __init__(self, rcfg: QuantumRAGConfig) -> None:
        self.rcfg = rcfg
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.rcfg.db_path)
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA foreign_keys=ON;")
        return con

    def _init_db(self) -> None:
        con = self._conn()
        try:
            con.executescript(
                f"""
                CREATE TABLE IF NOT EXISTS {self.rcfg.table} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_utc INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    key TEXT NOT NULL,
                    meta_json TEXT NOT NULL,
                    vec_dim INTEGER NOT NULL,
                    vec_blob BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_{self.rcfg.table}_kind_key ON {self.rcfg.table}(kind, key);
                """
            )
            con.commit()
        finally:
            con.close()

    def upsert(self, kind: str, key: str, meta: Dict[str, Any], vec: Any) -> int:
        _np_required()
        v = np.asarray(vec, dtype=np.float32)
        blob = v.tobytes()
        meta_json = json.dumps(meta, ensure_ascii=False)
        created = now_utc()
        con = self._conn()
        try:
            cur = con.cursor()
            cur.execute(
                f"SELECT id FROM {self.rcfg.table} WHERE kind=? AND key=? ORDER BY id DESC LIMIT 1",
                (str(kind), str(key)),
            )
            row = cur.fetchone()
            if row:
                rid = int(row[0])
                cur.execute(
                    f"UPDATE {self.rcfg.table} SET created_utc=?, meta_json=?, vec_dim=?, vec_blob=? WHERE id=?",
                    (created, meta_json, int(v.size), sqlite3.Binary(blob), rid),
                )
                con.commit()
                return rid
            cur.execute(
                f"INSERT INTO {self.rcfg.table} (created_utc, kind, key, meta_json, vec_dim, vec_blob) VALUES (?, ?, ?, ?, ?, ?)",
                (created, str(kind), str(key), meta_json, int(v.size), sqlite3.Binary(blob)),
            )
            con.commit()
            return int(cur.lastrowid)
        finally:
            con.close()

    def _load_all(self, kind: Optional[str] = None) -> List[Tuple[int, str, str, Dict[str, Any], Any]]:
        _np_required()
        con = self._conn()
        try:
            cur = con.cursor()
            if kind is None:
                cur.execute(f"SELECT id, kind, key, meta_json, vec_dim, vec_blob FROM {self.rcfg.table} ORDER BY id DESC")
            else:
                cur.execute(
                    f"SELECT id, kind, key, meta_json, vec_dim, vec_blob FROM {self.rcfg.table} WHERE kind=? ORDER BY id DESC",
                    (str(kind),),
                )
            out: List[Tuple[int, str, str, Dict[str, Any], Any]] = []
            for rid, k, key, meta_json, dim, blob in cur.fetchall():
                meta = json.loads(meta_json)
                vec = np.frombuffer(blob, dtype=np.float32, count=int(dim)).astype(np.float64, copy=False)
                out.append((int(rid), str(k), str(key), meta, _normalize(vec)))
            return out
        finally:
            con.close()

    def search(self, query_vec: Any, top_k: int = 6, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        _np_required()
        q = _normalize(np.asarray(query_vec, dtype=np.float64))
        rows = self._load_all(kind=kind)
        scored: List[Tuple[float, Dict[str, Any]]] = []
        for rid, k, key, meta, vec in rows:
            s = _cosine(q, vec)
            scored.append((s, {"id": rid, "kind": k, "key": key, "score": float(s), "meta": meta}))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [x[1] for x in scored[: max(1, int(top_k))]]


class QuantumRAGLLM:
    def __init__(self, llm: LLMConfig) -> None:
        self.llm = llm

    def _api_key(self) -> str:
        return (os.environ.get(self.llm.api_key_env, "") or "").strip()

    async def chat(self, system: str, user: str) -> Dict[str, Any]:
        key = self._api_key()
        if not key:
            return {"ok": False, "error": f"{self.llm.api_key_env} missing", "text": ""}

        payload = {
            "model": self.llm.model,
            "input": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.2,
            "max_output_tokens": 900,
        }

        try:
            async with httpx.AsyncClient(timeout=self.llm.timeout_s) as client:
                r = await client.post(
                    self.llm.endpoint,
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    json=payload,
                )
                if r.status_code >= 400:
                    try:
                        j = r.json()
                        msg = j.get("error", {}).get("message") or str(j.get("error") or "")
                    except Exception:
                        msg = r.text[:500]
                    return {"ok": False, "error": f"HTTP {r.status_code}: {msg}", "text": ""}
                j = r.json()
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}", "text": ""}

        text = extract_responses_text(j) or ""
        return {"ok": True, "error": "", "text": text, "raw": j}


class QuantumRGBRAGSystem:
    def __init__(self, qcfg: QuantumRGBConfig, rcfg: QuantumRAGConfig, llm_cfg: LLMConfig) -> None:
        self.embedder = QuantumRGBEmbedder(qcfg)
        self.store = QuantumRAGStore(rcfg)
        self.llm = QuantumRAGLLM(llm_cfg)

    def index_beam(self, key: str, beam_tokens: Sequence[str], meta: Optional[Dict[str, Any]] = None) -> int:
        vec = self.embedder.embed_colorbeam(beam_tokens)
        m = dict(meta or {})
        m.update(
            {
                "created_utc": now_utc(),
                "engine": "numpy_qsim",
                "qutrit": bool(self.embedder.uses_qutrit),
                "levels_per_channel": int(self.embedder.qcfg.levels_per_channel),
                "depth": int(self.embedder.qcfg.depth),
                "shots": int(self.embedder.qcfg.shots),
                "beam_len": int(len(list(beam_tokens))),
            }
        )
        return self.store.upsert(kind="beam", key=key, meta=m, vec=vec)

    def _query_seed_rgb(self, query: str) -> Tuple[int, int, int]:
        h = hashlib.sha256(query.encode("utf-8")).digest()
        seed = int.from_bytes(h[:8], "big") / 2**64
        r = int(seed * 255)
        g = int(((seed * 1.61803398875) % 1.0) * 255)
        b = int(((seed * 2.41421356237) % 1.0) * 255)
        return r, g, b

    def retrieve(self, query: str, top_k: int = 6, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        r, g, b = self._query_seed_rgb(query)
        qvec = self.embedder.embed_rgb(r, g, b)
        return self.store.search(qvec, top_k=top_k, kind=kind)

    async def answer(self, query: str, top_k: int = 6, kind: Optional[str] = None) -> Dict[str, Any]:
        hits = self.retrieve(query, top_k=top_k, kind=kind)
        ctx_lines: List[str] = []
        for h in hits:
            ctx_lines.append(
                json.dumps(
                    {
                        "id": h.get("id"),
                        "kind": h.get("kind"),
                        "key": h.get("key"),
                        "score": h.get("score"),
                        "meta": h.get("meta") or {},
                    },
                    ensure_ascii=False,
                )
            )
        system = "Use retrieved records as context. Return Markdown."
        user = (
            f"Query:\n{query}\n\n"
            f"Retrieved records (JSONL):\n" + "\n".join(ctx_lines) + "\n\n"
            "Return:\n"
            "- A direct answer\n"
            "- A justification referencing record keys\n"
            "- Next actions (3 bullets)\n"
        )
        resp = await self.llm.chat(system, user)
        return {"query": query, "hits": hits, "llm": resp}

    def describe(self) -> Dict[str, Any]:
        return {
            "qutrit": bool(self.embedder.uses_qutrit),
            "levels_per_channel": int(self.embedder.qcfg.levels_per_channel),
            "depth": int(self.embedder.qcfg.depth),
            "shots": int(self.embedder.qcfg.shots),
            "seed": int(self.embedder.qcfg.seed),
            "embedding_dim": int(self.embedder.embedding_dim),
            "db_path": self.store.rcfg.db_path,
            "table": self.store.rcfg.table,
            "llm_model": self.llm.llm.model,
            "llm_endpoint": self.llm.llm.endpoint,
        }


@dataclass
class ScanConfig:
    city: str = "greenville_woodruff"
    halocline_str: str = "34.84,-82.26,290"
    segments: int = 12
    beams_local: int = 8
    polymorph: bool = False
    polymorph_period_s: int = 60
    quantum_mode: bool = True

    # TEST-SIM priors
    real_world_inference: bool = False

    # runtime (LIVE is default)
    runtime_mode: str = "live"  # "simulated" | "live"
    sensor_feed_path: str = "live_sensors.jsonl"
    roadmap_path: str = ""

    # LIVE filtering + telemetry
    live_fir_window: int = 5
    live_iir_alpha: float = 0.35
    live_blend_iir: float = 0.6
    live_telemetry_path: str = "live_telemetry.jsonl"

    # vault
    resonance_phrase: str = ""

    # QRAG
    qrag_levels: int = 3
    qrag_depth: int = 2
    qrag_shots: int = 0
    qrag_seed: int = 7
    qrag_prefer_qutrit: bool = True
    qrag_top_k: int = 6


@dataclass
class State:
    cfg: ScanConfig = dataclasses.field(default_factory=ScanConfig)
    beam: List[str] = dataclasses.field(default_factory=fail_closed_beam)
    beam_audit: Dict[str, Any] = dataclasses.field(default_factory=dict)
    segs: List[Segment] = dataclasses.field(default_factory=list)
    seg_meta: Dict[str, Any] = dataclasses.field(default_factory=dict)
    routes: List[Route] = dataclasses.field(default_factory=list)
    route_meta: Dict[str, Any] = dataclasses.field(default_factory=dict)
    selected: int = 0
    guidance_md: str = ""
    guidance_audit: Dict[str, Any] = dataclasses.field(default_factory=dict)
    beam_id: Optional[int] = None

    qrag_enabled: bool = False
    qrag_status: str = ""
    qrag_last_hits: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    qrag_last_answer: str = ""
    qrag_last_error: str = ""

    # LIVE runtime
    live_frames: List[LiveSensorFrame] = dataclasses.field(default_factory=list)
    live_telemetry: List[LiveTelemetryRecord] = dataclasses.field(default_factory=list)
    live_tel_written: int = 0


def qrag_make(cfg: ScanConfig) -> QuantumRGBRAGSystem:
    qcfg = QuantumRGBConfig(
        levels_per_channel=int(cfg.qrag_levels),
        depth=int(cfg.qrag_depth),
        shots=int(cfg.qrag_shots),
        seed=int(cfg.qrag_seed),
        prefer_qutrit=bool(cfg.qrag_prefer_qutrit),
    )
    rcfg = QuantumRAGConfig(db_path="quantum_rgb_rag.sqlite", table="items")
    llm_cfg = LLMConfig(api_key_env="OPENAI_API_KEY", model=MODEL_NAME, endpoint=OPENAI_RESPONSES_URL, timeout_s=45.0)
    return QuantumRGBRAGSystem(qcfg, rcfg, llm_cfg)


# ============================
# TUI (optional)
# ============================

if App is not None:

    class StatusLog(Log):
        def write_status(self, s: str) -> None:
            try:
                self.write_line(s)
            except Exception:
                pass

    class Home(Screen):
        BINDINGS = [("q", "app.quit", "Quit"), ("escape", "app.quit", "Quit")]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Vertical(id="home_root"):
                yield Label("Quantum ColorBeam RoadScanner + QRAG (numpy qsim)", id="home_title")
                yield Label("Use arrow keys + Enter.", id="home_subtitle")
                lv = ListView(id="home_menu")
                yield lv
                yield Footer()

        def on_mount(self) -> None:
            lv = self.query_one("#home_menu", ListView)
            for label, key in [
                ("Configure", "cfg"),
                ("Generate Beam", "beam"),
                ("Simulate Segments", "seg"),
                ("Route Selector", "route"),
                ("Live Sensing", "live"),
                ("Vault", "vault"),
                ("Quantum RAG", "qrag"),
                ("Quit", "quit"),
            ]:
                lv.append(ListItem(Label(label), name=key))
            lv.index = 0

        @on(ListView.Selected)
        def on_sel(self, e: ListView.Selected) -> None:
            k = e.item.name or ""
            if k == "cfg":
                self.app.push_screen(CfgScreen())
            elif k == "beam":
                self.app.push_screen(BeamScreen())
            elif k == "seg":
                self.app.push_screen(SegScreen())
            elif k == "route":
                self.app.push_screen(RouteScreen())
            elif k == "live":
                self.app.push_screen(LiveScreen())
            elif k == "vault":
                self.app.push_screen(VaultScreen())
            elif k == "qrag":
                self.app.push_screen(QRAGScreen())
            else:
                self.app.exit()

    class Work(Screen):
        BINDINGS = [("escape", "pop_screen", "Back"), ("q", "app.quit", "Quit")]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Vertical(id="root"):
                with Horizontal(id="top"):
                    with Vertical(id="left"):
                        yield Static("", id="left_title")
                        yield Container(id="left_body")
                    with Vertical(id="right"):
                        yield Static("", id="right_title")
                        yield Markdown("", id="right_md")
                yield StatusLog(id="status_log", highlight=False)
            yield Footer()

        def set_titles(self, l: str, r: str) -> None:
            self.query_one("#left_title", Static).update(l)
            self.query_one("#right_title", Static).update(r)

        def set_md(self, md: str) -> None:
            self.query_one("#right_md", Markdown).update(md)

        def status(self, s: str) -> None:
            self.query_one("#status_log", StatusLog).write_status(s)

    class CfgScreen(Work):
        def on_mount(self) -> None:
            self.set_titles("Configure", "Preview")
            b = self.query_one("#left_body", Container)
            st = self.app.state
            b.mount(
                Vertical(
                    Label("City key"),
                    Input(value=st.cfg.city, id="city"),
                    Label('Halocline "lat,lon,depth_m"'),
                    Input(value=st.cfg.halocline_str, id="halo"),
                    Label("Segments"),
                    Input(value=str(st.cfg.segments), id="segs"),
                    Label("Local beams"),
                    Input(value=str(st.cfg.beams_local), id="beams"),
                    Horizontal(Label("Polymorph"), Switch(value=st.cfg.polymorph, id="poly")),
                    Label("Polymorph period (seconds)"),
                    Input(value=str(st.cfg.polymorph_period_s), id="poly_p"),
                    Horizontal(Label("Quantum mode (sim)"), Switch(value=st.cfg.quantum_mode, id="qm")),
                    Horizontal(Label("Real-world inference (test sim priors)"), Switch(value=st.cfg.real_world_inference, id="rwi")),
                    Horizontal(Label("RUNTIME: LIVE sensing (default)"), Switch(value=(st.cfg.runtime_mode == "live"), id="live")),
                    Label("LIVE sensor feed path (JSONL)"),
                    Input(value=str(st.cfg.sensor_feed_path or ""), id="sensor_path"),
                    Label("Roadmap JSON (optional: road + start/end GPS per segment)"),
                    Input(value=str(st.cfg.roadmap_path or ""), id="roadmap_path"),
                    Label("LIVE FIR window (rolling mean)"),
                    Input(value=str(st.cfg.live_fir_window), id="fir_window"),
                    Label("LIVE IIR alpha (EMA 0..1)"),
                    Input(value=str(st.cfg.live_iir_alpha), id="iir_alpha"),
                    Label("LIVE blend_iir (0..1; 1=all IIR, 0=all FIR)"),
                    Input(value=str(st.cfg.live_blend_iir), id="blend_iir"),
                    Label("LIVE telemetry output (JSONL)"),
                    Input(value=str(st.cfg.live_telemetry_path or ""), id="tel_path"),
                    Label("Resonance phrase (vault decrypt)"),
                    Input(value=st.cfg.resonance_phrase, password=True, id="res"),
                    Label("QRAG levels/channel"),
                    Input(value=str(st.cfg.qrag_levels), id="q_levels"),
                    Label("QRAG depth"),
                    Input(value=str(st.cfg.qrag_depth), id="q_depth"),
                    Label("QRAG shots (0=analytic)"),
                    Input(value=str(st.cfg.qrag_shots), id="q_shots"),
                    Label("QRAG seed"),
                    Input(value=str(st.cfg.qrag_seed), id="q_seed"),
                    Horizontal(Label("Prefer qutrit"), Switch(value=st.cfg.qrag_prefer_qutrit, id="q_qutrit")),
                    Label("QRAG top_k"),
                    Input(value=str(st.cfg.qrag_top_k), id="q_topk"),
                    Horizontal(Button("Save", id="save", variant="primary"), Button("Back", id="back")),
                )
            )
            self.refresh()

        def refresh(self) -> None:
            md = beam_md(self.app.state.beam, self.app.state.beam_audit)
            md += "\n\n---\n\n" + routes_md(self.app.state.routes)
            cfg = self.app.state.cfg
            md += "\n\n---\n\n# Runtime\n\n"
            md += f"- runtime_mode: `{cfg.runtime_mode}`\n"
            md += f"- sensor_feed_path: `{cfg.sensor_feed_path}`\n"
            md += f"- roadmap_path: `{cfg.roadmap_path}`\n"
            md += f"- live_fir_window: `{cfg.live_fir_window}`  live_iir_alpha: `{cfg.live_iir_alpha}`  live_blend_iir: `{cfg.live_blend_iir}`\n"
            md += f"- live_telemetry_path: `{cfg.live_telemetry_path}`\n"
            self.set_md(md)

        @on(Button.Pressed, "#save")
        def on_save(self) -> None:
            try:
                st = self.app.state
                city = self.query_one("#city", Input).value.strip() or "greenville_woodruff"
                halo = self.query_one("#halo", Input).value.strip() or "34.84,-82.26,290"
                segs = int(self.query_one("#segs", Input).value.strip() or "12")
                beams = int(self.query_one("#beams", Input).value.strip() or "8")
                poly = bool(self.query_one("#poly", Switch).value)
                poly_p = int(self.query_one("#poly_p", Input).value.strip() or "60")
                qm = bool(self.query_one("#qm", Switch).value)
                rwi = bool(self.query_one("#rwi", Switch).value)
                live = bool(self.query_one("#live", Switch).value)
                sensor_path = self.query_one("#sensor_path", Input).value.strip()
                roadmap_path = self.query_one("#roadmap_path", Input).value.strip()
                fir_window = int(self.query_one("#fir_window", Input).value.strip() or "5")
                iir_alpha = float(self.query_one("#iir_alpha", Input).value.strip() or "0.35")
                blend_iir = float(self.query_one("#blend_iir", Input).value.strip() or "0.6")
                tel_path = self.query_one("#tel_path", Input).value.strip()
                res = self.query_one("#res", Input).value

                q_levels = int(self.query_one("#q_levels", Input).value.strip() or "3")
                q_depth = int(self.query_one("#q_depth", Input).value.strip() or "2")
                q_shots = int(self.query_one("#q_shots", Input).value.strip() or "0")
                q_seed = int(self.query_one("#q_seed", Input).value.strip() or "7")
                q_qutrit = bool(self.query_one("#q_qutrit", Switch).value)
                q_topk = int(self.query_one("#q_topk", Input).value.strip() or "6")

                _ = tuple(float(x.strip()) for x in halo.split(","))

                st.cfg.city = city
                st.cfg.halocline_str = halo
                st.cfg.segments = max(2, min(64, segs))
                st.cfg.beams_local = max(1, min(16, beams))
                st.cfg.polymorph = poly
                st.cfg.polymorph_period_s = max(10, min(3600, poly_p))
                st.cfg.quantum_mode = qm
                st.cfg.real_world_inference = rwi
                st.cfg.runtime_mode = "live" if live else "simulated"
                st.cfg.sensor_feed_path = sensor_path
                st.cfg.roadmap_path = roadmap_path

                st.cfg.live_fir_window = max(1, min(60, int(fir_window)))
                st.cfg.live_iir_alpha = clamp(float(iir_alpha), 0.0, 1.0)
                st.cfg.live_blend_iir = clamp(float(blend_iir), 0.0, 1.0)
                st.cfg.live_telemetry_path = tel_path

                st.cfg.resonance_phrase = res

                st.cfg.qrag_levels = max(2, min(8, q_levels))
                st.cfg.qrag_depth = max(0, min(6, q_depth))
                st.cfg.qrag_shots = max(0, min(20000, q_shots))
                st.cfg.qrag_seed = int(q_seed)
                st.cfg.qrag_prefer_qutrit = q_qutrit
                st.cfg.qrag_top_k = max(1, min(20, q_topk))

                self.status("[OK] config saved")
                self.refresh()
            except Exception as e:
                self.status(f"[ERR] save failed: {type(e).__name__}: {e}")

        @on(Button.Pressed, "#back")
        def on_back(self) -> None:
            self.app.pop_screen()

    class BeamScreen(Work):
        def on_mount(self) -> None:
            self.set_titles("Generate Beam", "Beam Diagnostics")
            b = self.query_one("#left_body", Container)
            b.mount(
                Vertical(
                    Label("Generate a 50-token ColorBeam using OpenAI."),
                    Button("Generate Beam Now", id="gen", variant="primary"),
                    Button("Save Beam to Vault", id="save"),
                    Button("Back", id="back"),
                    Static("", id="api"),
                    Static("", id="err"),
                )
            )
            self._hint()
            self.refresh()

        def _hint(self) -> None:
            self.query_one("#api", Static).update(
                "OPENAI_API_KEY: OK" if os.environ.get("OPENAI_API_KEY", "").strip() else "OPENAI_API_KEY: MISSING"
            )

        def refresh(self) -> None:
            self.set_md(beam_md(self.app.state.beam, self.app.state.beam_audit))
            self.query_one("#err", Static).update(str(self.app.state.beam_audit.get("llm_error", "") or "")[:900])

        @on(Button.Pressed, "#gen")
        def on_gen(self) -> None:
            self._hint()
            api_key = os.environ.get("OPENAI_API_KEY", "").strip()
            if not api_key:
                self.status("[WARN] OPENAI_API_KEY missing; using fail-closed beam.")
                self.app.state.beam = fail_closed_beam()
                self.app.state.beam_audit = {"llm_ok": False, "llm_error": "OPENAI_API_KEY missing", "ts": now_utc()}
                self.refresh()
                return
            cfg = self.app.state.cfg
            self.status("[RUN] generating beam...")

            async def _run() -> None:
                try:
                    hal = tuple(float(x.strip()) for x in cfg.halocline_str.split(","))
                    client = OpenAIBeamClient(api_key=api_key)
                    beam, audit = await client.generate_beam(
                        cfg.city,
                        hal,
                        cfg.segments,
                        cfg.beams_local,
                        cfg.polymorph,
                        cfg.quantum_mode,
                        cfg.real_world_inference,
                    )
                    self.app.state.beam = beam
                    self.app.state.beam_audit = audit
                    self.call_from_thread(
                        lambda: self.status("[OK] beam updated" if audit.get("beam_ok") else f"[WARN] beam invalid: {audit.get('beam_msg')}")
                    )
                    self.call_from_thread(self.refresh)
                except Exception as e:
                    self.app.state.beam = fail_closed_beam()
                    self.app.state.beam_audit = {"llm_ok": False, "llm_error": f"{type(e).__name__}: {e}", "ts": now_utc()}
                    self.call_from_thread(lambda: self.status(f"[ERR] beam error: {type(e).__name__}: {e}"))
                    self.call_from_thread(self.refresh)

            self.app.run_worker(_run(), exclusive=True)

        @on(Button.Pressed, "#save")
        def on_save(self) -> None:
            try:
                cfg = self.app.state.cfg
                bid = self.app.vault.put_beam(cfg.city, cfg.halocline_str, MODEL_NAME, self.app.state.beam, self.app.state.beam_audit)
                self.app.state.beam_id = bid
                self.status(f"[OK] saved beam id={bid}")
            except Exception as e:
                self.status(f"[ERR] save failed: {type(e).__name__}: {e}")

        @on(Button.Pressed, "#back")
        def on_back(self) -> None:
            self.app.pop_screen()

    class SegScreen(Work):
        def on_mount(self) -> None:
            self.set_titles("Simulate Segments", "Beam + Segment Snapshot")
            b = self.query_one("#left_body", Container)
            b.mount(
                Vertical(
                    Label("Generate segments from config + beam."),
                    Button("Simulate Segments Now", id="sim", variant="primary"),
                    Button("Back", id="back"),
                    Static("", id="hint"),
                )
            )
            self._hint()
            self.refresh()

        def _hint(self) -> None:
            st = self.app.state
            self.query_one("#hint", Static).update(
                f"segments: {st.cfg.segments}  quantum_mode: {st.cfg.quantum_mode}  real_world_inference: {st.cfg.real_world_inference}  runtime_mode: {st.cfg.runtime_mode}"
            )

        def refresh(self) -> None:
            st = self.app.state
            md = beam_md(st.beam, st.beam_audit)
            md += "\n\n---\n\n"
            if st.segs:
                md += "# Segments (first 10)\n\n"
                for s in st.segs[:10]:
                    md += (
                        f"- **{s.idx:02d}** {s.road or s.name}\n"
                        f"  - gps: start=({s.start_gps[0]:.6f},{s.start_gps[1]:.6f}) end=({s.end_gps[0]:.6f},{s.end_gps[1]:.6f})\n"
                        f"  - risk={s.risk:.3f} flow={s.flow:.3f} time={s.time:.3f} color={s.risk_hex} qphase={s.qphase}\n"
                    )
                    if (st.cfg.runtime_mode or "").strip().lower() == "live":
                        md += f"  - live_ts={s.live_ts_utc} debris={s.debris_detected} sev={s.debris_severity:.2f}\n"
                        if s.debris_gps:
                            md += f"  - debris_gps=({s.debris_gps[0]:.6f},{s.debris_gps[1]:.6f})\n"
                        md += f"  - accident_p: 2m={s.accident_p_2_min:.2f} 5m={s.accident_p_5_min:.2f} 10m={s.accident_p_10_min:.2f}\n"
            else:
                md += "# Segments\n\nNo segments yet."
            self.set_md(md)

        @on(Button.Pressed, "#sim")
        def on_sim(self) -> None:
            try:
                st = self.app.state
                cfg = st.cfg
                hal = tuple(float(x.strip()) for x in cfg.halocline_str.split(","))
                ok, _ = verify_beam(st.beam, enforce_checksum=True)
                beam = st.beam if ok else fail_closed_beam()

                frames: List[LiveSensorFrame] = []
                if (cfg.runtime_mode or "").strip().lower() == "live":
                    raw = load_live_frames_jsonl(cfg.sensor_feed_path)
                    pipe = LiveTelemetryPipeline(
                        LiveFilterConfig(
                            fir_window=int(cfg.live_fir_window),
                            iir_alpha=float(cfg.live_iir_alpha),
                            blend_iir=float(cfg.live_blend_iir),
                        )
                    )
                    frames, tel = pipe.ingest(raw)
                    st.live_frames = frames
                    st.live_telemetry = tel
                    st.live_tel_written = write_live_telemetry_jsonl(cfg.live_telemetry_path, tel)

                roadmap = load_roadmap(cfg.roadmap_path)
                segs, meta = simulate_segments(
                    cfg.city,
                    cfg.segments,
                    hal,
                    beam,
                    cfg.polymorph,
                    cfg.polymorph_period_s,
                    cfg.quantum_mode,
                    runtime_mode=cfg.runtime_mode,
                    live_frames=frames,
                    roadmap=roadmap,
                )

                st.segs, st.seg_meta = segs, meta
                st.routes, st.route_meta, st.selected = [], {}, 0
                st.guidance_md, st.guidance_audit = "", {}
                self.status(f"[OK] simulated {len(segs)} segments qphase={meta.get('qphase')}")
                self._hint()
                self.refresh()
            except Exception as e:
                self.status(f"[ERR] simulate failed: {type(e).__name__}: {e}")

        @on(Button.Pressed, "#back")
        def on_back(self) -> None:
            self.app.pop_screen()

    class RouteScreen(Work):
        def on_mount(self) -> None:
            self.set_titles("Route Selector", "Routes + Selected + Guidance")
            b = self.query_one("#left_body", Container)
            t = DataTable(id="tbl")
            t.cursor_type = "row"
            t.add_columns("Rank", "Score", "Time", "Risk", "Var", "Rob", "Tag", "Path")
            b.mount(
                Vertical(
                    Label("Plan routes and generate English guidance."),
                    Button("Plan Routes Now", id="plan", variant="primary"),
                    Button("Generate English Guidance", id="guide"),
                    Button("Back", id="back"),
                    Static("", id="hint"),
                    t,
                )
            )
            self._hint()
            self.refresh()

        def _hint(self) -> None:
            st = self.app.state
            api_ok = bool(os.environ.get("OPENAI_API_KEY", "").strip())
            beam_ok, _ = verify_beam(st.beam, enforce_checksum=True)
            self.query_one("#hint", Static).update(
                f"API: {'OK' if api_ok else 'MISSING'} · Beam: {'OK' if beam_ok else 'INVALID'} · Segments: {len(st.segs)} · Quantum: {st.cfg.quantum_mode} · Real-world priors: {st.cfg.real_world_inference} · Runtime: {st.cfg.runtime_mode}"
            )

        def refresh(self) -> None:
            st = self.app.state
            md = routes_md(st.routes)
            if st.routes:
                i = max(0, min(int(st.selected), len(st.routes) - 1))
                r = st.routes[i]
                md += "\n\n---\n\n# Selected Route\n\n"
                md += f"- rank: **{i+1}**\n- path: `{ ' → '.join(map(str, r.nodes)) }`\n- score: `{r.score:.3f}` time:`{r.time:.3f}` risk:`{r.risk:.3f}`\n- var: `{r.var:.4f}` robust:`{r.robust:.3f}`\n"
                if r.explanation:
                    md += "\n```\n" + r.explanation.strip() + "\n```\n"
            if isinstance(st.guidance_audit, dict) and st.guidance_audit.get("ok") is False:
                md += "\n\n---\n\n# English Guidance\n\n**Error:** " + str(st.guidance_audit.get("error", "unknown"))[:1400]
            elif st.guidance_md.strip():
                md += "\n\n---\n\n# English Guidance\n\n" + st.guidance_md.strip()
            self.set_md(md)

            tbl = self.query_one("#tbl", DataTable)
            tbl.clear()
            for i, r in enumerate(st.routes):
                tbl.add_row(
                    str(i + 1),
                    f"{r.score:.3f}",
                    f"{r.time:.3f}",
                    f"{r.risk:.3f}",
                    f"{r.var:.4f}",
                    f"{r.robust:.3f}",
                    r.tag,
                    "→".join(map(str, r.nodes)),
                )
            if st.routes:
                tbl.cursor_coordinate = (int(st.selected), 0)

        @on(DataTable.RowSelected, "#tbl")
        def on_row(self) -> None:
            tbl = self.query_one("#tbl", DataTable)
            if tbl.row_count:
                self.app.state.selected = int(tbl.cursor_row or 0)
                self.refresh()

        @on(Button.Pressed, "#plan")
        def on_plan(self) -> None:
            st = self.app.state
            if not st.segs:
                self.status("[WARN] no segments; simulate first")
                return
            cfg = st.cfg
            ok, _ = verify_beam(st.beam, enforce_checksum=True)
            beam = st.beam if ok else fail_closed_beam()
            routes, meta = plan_routes(cfg.city, st.segs, beam, 5, cfg.polymorph, cfg.polymorph_period_s, cfg.quantum_mode)
            st.routes, st.route_meta, st.selected = routes, meta, 0
            st.guidance_md, st.guidance_audit = "", {}
            self.status(f"[OK] planned {len(routes)} routes qphase={meta.get('qphase')}")
            self._hint()
            self.refresh()

        @on(Button.Pressed, "#guide")
        def on_guide(self) -> None:
            st = self.app.state
            if not st.routes or not st.segs:
                self.status("[WARN] need routes + segments")
                return
            api_key = os.environ.get("OPENAI_API_KEY", "").strip()
            if not api_key:
                st.guidance_md = ""
                st.guidance_audit = {"ok": False, "error": "OPENAI_API_KEY missing", "ts": now_utc()}
                self.status("[WARN] OPENAI_API_KEY missing")
                self._hint()
                self.refresh()
                return
            cfg = st.cfg
            i = max(0, min(int(st.selected), len(st.routes) - 1))
            route = st.routes[i]
            ok, _ = verify_beam(st.beam, enforce_checksum=True)
            beam = st.beam if ok else fail_closed_beam()
            self.status("[RUN] generating guidance...")

            async def _run() -> None:
                try:
                    hal = tuple(float(x.strip()) for x in cfg.halocline_str.split(","))
                    client = OpenAIGuidanceClient(api_key=api_key)
                    md, audit = await client.generate(
                        cfg.city,
                        hal,
                        beam,
                        st.segs,
                        route,
                        cfg.quantum_mode,
                        cfg.real_world_inference,
                        runtime_mode=cfg.runtime_mode,
                    )
                    st.guidance_md, st.guidance_audit = md, audit
                    self.call_from_thread(lambda: self.status("[OK] guidance ready" if audit.get("ok") else f"[ERR] guidance: {audit.get('error')}"))
                    self.call_from_thread(self._hint)
                    self.call_from_thread(self.refresh)
                except Exception as e:
                    st.guidance_md = ""
                    st.guidance_audit = {"ok": False, "error": f"{type(e).__name__}: {e}", "ts": now_utc()}
                    self.call_from_thread(lambda: self.status(f"[ERR] guidance error: {type(e).__name__}: {e}"))
                    self.call_from_thread(self._hint)
                    self.call_from_thread(self.refresh)

            self.app.run_worker(_run(), exclusive=True)

        @on(Button.Pressed, "#back")
        def on_back(self) -> None:
            self.app.pop_screen()

    class LiveScreen(Work):
        def on_mount(self) -> None:
            self.set_titles("Live Sensing", "Live Snapshot")
            b = self.query_one("#left_body", Container)
            st = self.app.state
            b.mount(
                Vertical(
                    Label("LIVE mode ingests JSONL frames and overlays debris + accident forecasts onto segments."),
                    Label("Sensor feed path (JSONL)"),
                    Input(value=str(st.cfg.sensor_feed_path or ""), id="live_path"),
                    Button("Ingest LIVE Frames", id="ingest", variant="primary"),
                    Button("Back", id="back"),
                    Static("", id="hint"),
                )
            )
            self.refresh()

        def refresh(self) -> None:
            st = self.app.state
            mode = (st.cfg.runtime_mode or "").strip().lower()
            self.query_one("#hint", Static).update(
                f"runtime_mode={mode}  frames_loaded={len(st.live_frames)}  telemetry_rows={len(st.live_telemetry)}  written={st.live_tel_written}"
            )
            md = "# LIVE\n\n"
            md += f"- runtime_mode: `{mode}`\n"
            md += f"- feed_path: `{st.cfg.sensor_feed_path}`\n"
            md += f"- frames_loaded: `{len(st.live_frames)}`\n"
            md += f"- fir_window: `{st.cfg.live_fir_window}`  iir_alpha: `{st.cfg.live_iir_alpha}`  blend_iir: `{st.cfg.live_blend_iir}`\n"
            md += f"- telemetry_path: `{st.cfg.live_telemetry_path}`  written_rows: `{st.live_tel_written}`\n\n"

            if st.live_frames:
                md += "## Latest frames (up to 12)\n\n"
                latest = sorted(st.live_frames, key=lambda x: int(x.ts_utc), reverse=True)[:12]
                for fr in latest:
                    probs = predict_accident_probability(fr)
                    md += (
                        f"- seg={fr.segment_idx:02d} ts={fr.ts_utc} gps=({fr.gps[0]:.6f},{fr.gps[1]:.6f}) "
                        f"debris={fr.debris_detected} sev={fr.debris_severity:.2f} "
                        f"p2={probs['p_2_min']:.2f} p5={probs['p_5_min']:.2f} p10={probs['p_10_min']:.2f}\n"
                    )
            else:
                md += "## Frames\n\n(none loaded)\n"

            if st.live_telemetry:
                md += "\n## Telemetry (latest 16)\n\n"
                for r in list(st.live_telemetry)[-16:]:
                    md += (
                        f"- seg={r.segment_idx:02d} ts={r.ts_utc} metric={r.metric} "
                        f"raw={r.raw:.2f} fir={r.fir:.2f} iir={r.iir:.2f} blend={r.blended:.2f} spike={r.ir_spike:.2f}\n"
                    )

            self.set_md(md)

        @on(Button.Pressed, "#ingest")
        def on_ingest(self) -> None:
            st = self.app.state
            path = self.query_one("#live_path", Input).value.strip()
            st.cfg.sensor_feed_path = path
            raw = load_live_frames_jsonl(path)
            pipe = LiveTelemetryPipeline(
                LiveFilterConfig(
                    fir_window=int(st.cfg.live_fir_window),
                    iir_alpha=float(st.cfg.live_iir_alpha),
                    blend_iir=float(st.cfg.live_blend_iir),
                )
            )
            frames, tel = pipe.ingest(raw)
            st.live_frames = frames
            st.live_telemetry = tel
            st.live_tel_written = write_live_telemetry_jsonl(st.cfg.live_telemetry_path, tel)
            self.status(f"[OK] ingested {len(frames)} live frames · telemetry_rows={len(tel)} · written={st.live_tel_written}")
            self.refresh()

        @on(Button.Pressed, "#back")
        def on_back(self) -> None:
            self.app.pop_screen()

    class VaultScreen(Work):
        def on_mount(self) -> None:
            self.set_titles("Vault", "Details")
            b = self.query_one("#left_body", Container)
            t = DataTable(id="beams_tbl")
            t.cursor_type = "row"
            t.add_columns("ID", "Created", "City", "Halo", "Sig", "OK", "Enc")
            b.mount(
                Vertical(
                    Label("Saved Beams"),
                    Button("Refresh", id="refresh", variant="primary"),
                    Button("Load Selected Beam", id="load"),
                    Button("Back", id="back"),
                    t,
                )
            )
            self.refresh_table()
            self.set_md("# Vault\n\nSelect a row and load it.")

        def refresh_table(self) -> None:
            t = self.query_one("#beams_tbl", DataTable)
            t.clear()
            rows = self.app.vault.list_beams(limit=50)
            for bid, created, city, halo, sig, ok, enc in rows:
                t.add_row(
                    str(bid),
                    time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(created)),
                    city,
                    halo,
                    sig,
                    str(ok),
                    str(enc),
                )
            if rows:
                t.cursor_coordinate = (0, 0)

        def selected_beam_id(self) -> Optional[int]:
            t = self.query_one("#beams_tbl", DataTable)
            if t.row_count <= 0:
                return None
            try:
                row = t.get_row_at(t.cursor_row)
                return int(row[0])
            except Exception:
                return None

        @on(Button.Pressed, "#refresh")
        def on_refresh(self) -> None:
            self.refresh_table()
            self.status("[OK] refreshed")

        @on(Button.Pressed, "#load")
        def on_load(self) -> None:
            try:
                bid = self.selected_beam_id()
                if bid is None:
                    self.status("[WARN] select a row")
                    return
                payload = self.app.vault.load_beam(bid, self.app.state.cfg.resonance_phrase)
                tokens = payload.get("beam_tokens") or payload.get("beam", {}).get("beam_tokens")
                audit = payload.get("audit") or payload.get("beam", {}).get("audit") or {}
                if isinstance(tokens, list):
                    self.app.state.beam = [str(x).strip() for x in tokens]
                if isinstance(audit, dict):
                    self.app.state.beam_audit = dict(audit)
                self.app.state.beam_id = int(bid)
                self.status(f"[OK] loaded beam id={bid}")
                self.set_md(beam_md(self.app.state.beam, self.app.state.beam_audit))
            except Exception as e:
                self.status(f"[ERR] load failed: {type(e).__name__}: {e}")

        @on(Button.Pressed, "#back")
        def on_back(self) -> None:
            self.app.pop_screen()

    class QRAGScreen(Work):
        def on_mount(self) -> None:
            self.set_titles("Quantum RAG (numpy qsim)", "Results")
            b = self.query_one("#left_body", Container)
            b.mount(
                Vertical(
                    Label("Index current beam into quantum embedding store and query it."),
                    Button("Initialize QRAG", id="init", variant="primary"),
                    Button("Index Current Beam", id="index"),
                    Label("Query"),
                    Input(value="compare this beam to similar patterns", id="q"),
                    Button("Retrieve + Answer", id="ask"),
                    Button("Back", id="back"),
                    Static("", id="status"),
                    Static("", id="err"),
                )
            )
            self.refresh()

        def refresh(self) -> None:
            st = self.app.state
            self.query_one("#status", Static).update(st.qrag_status[:2000])
            self.query_one("#err", Static).update(st.qrag_last_error[:2000])
            md = "# QRAG\n\n"
            md += f"- enabled: `{st.qrag_enabled}`\n"
            md += f"- numpy: `{np is not None}`\n"
            md += "\n\n---\n\n"
            if st.qrag_last_hits:
                md += "## Hits\n\n"
                for h in st.qrag_last_hits[:10]:
                    md += f"- **{h.get('key')}** score=`{h.get('score'):.4f}` meta={json.dumps(h.get('meta') or {}, ensure_ascii=False)}\n"
            else:
                md += "## Hits\n\n(none)\n"
            md += "\n\n---\n\n"
            if st.qrag_last_answer.strip():
                md += "## Answer\n\n" + st.qrag_last_answer.strip() + "\n"
            else:
                md += "## Answer\n\n(none)\n"
            self.set_md(md)

        @on(Button.Pressed, "#init")
        def on_init(self) -> None:
            st = self.app.state
            try:
                sys = qrag_make(st.cfg)
                desc = sys.describe()
                self.app.qrag = sys
                st.qrag_enabled = True
                st.qrag_status = "initialized: " + json.dumps(desc, ensure_ascii=False)
                st.qrag_last_error = ""
            except Exception as e:
                st.qrag_enabled = False
                st.qrag_status = ""
                st.qrag_last_error = f"{type(e).__name__}: {e}"
            self.refresh()

        @on(Button.Pressed, "#index")
        def on_index(self) -> None:
            st = self.app.state
            if not getattr(self.app, "qrag", None):
                st.qrag_last_error = "not initialized"
                self.refresh()
                return
            ok, msg = verify_beam(st.beam, enforce_checksum=False)
            if not ok:
                st.qrag_last_error = f"beam invalid: {msg}"
                self.refresh()
                return
            try:
                key = f"beam:{beam_sig(st.beam)}"
                meta = {"city": st.cfg.city, "halocline": st.cfg.halocline_str, "ts": now_utc()}
                rid = self.app.qrag.index_beam(key=key, beam_tokens=st.beam, meta=meta)
                st.qrag_status = f"indexed beam key={key} id={rid}"
                st.qrag_last_error = ""
            except Exception as e:
                st.qrag_last_error = f"{type(e).__name__}: {e}"
            self.refresh()

        @on(Button.Pressed, "#ask")
        def on_ask(self) -> None:
            st = self.app.state
            if not getattr(self.app, "qrag", None):
                st.qrag_last_error = "not initialized"
                self.refresh()
                return
            query = self.query_one("#q", Input).value.strip()
            if not query:
                st.qrag_last_error = "empty query"
                self.refresh()
                return
            topk = int(max(1, min(20, st.cfg.qrag_top_k)))
            st.qrag_last_answer = ""
            st.qrag_last_error = ""
            self.status("[RUN] QRAG retrieve+answer...")

            async def _run() -> None:
                try:
                    hits = self.app.qrag.retrieve(query, top_k=topk, kind="beam")
                    out = await self.app.qrag.answer(query, top_k=topk, kind="beam")
                    st.qrag_last_hits = hits
                    llm = out.get("llm") or {}
                    if llm.get("ok"):
                        st.qrag_last_answer = str(llm.get("text") or "")
                        st.qrag_last_error = ""
                    else:
                        st.qrag_last_answer = ""
                        st.qrag_last_error = str(llm.get("error") or "llm error")
                    self.call_from_thread(lambda: self.status("[OK] QRAG done"))
                    self.call_from_thread(self.refresh)
                except Exception as e:
                    st.qrag_last_answer = ""
                    st.qrag_last_error = f"{type(e).__name__}: {e}"
                    self.call_from_thread(lambda: self.status(f"[ERR] QRAG failed: {type(e).__name__}: {e}"))
                    self.call_from_thread(self.refresh)

            self.app.run_worker(_run(), exclusive=True)

        @on(Button.Pressed, "#back")
        def on_back(self) -> None:
            self.app.pop_screen()

    class RoadScanner(App):
        CSS = """
        #home_root { padding: 1 2; }
        #home_title { text-style: bold; }
        #home_subtitle { color: $text-muted; margin-bottom: 1; }
        #top { height: 1fr; }
        #left { width: 44%; padding: 1; border: solid $surface; }
        #right { width: 56%; padding: 1; border: solid $surface; }
        #status_log { height: 10; border: solid $surface; padding: 0 1; }
        """

        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self.state = State()
            self.vault = VaultDB()
            self.qrag: Optional[QuantumRGBRAGSystem] = None

        def on_mount(self) -> None:
            self.push_screen(Home())


# ============================
# Headless + CLI
# ============================

async def headless(cfg: ScanConfig) -> int:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    hal = tuple(float(x.strip()) for x in cfg.halocline_str.split(","))

    if api_key:
        beam, audit = await OpenAIBeamClient(api_key=api_key).generate_beam(
            cfg.city,
            hal,
            cfg.segments,
            cfg.beams_local,
            cfg.polymorph,
            cfg.quantum_mode,
            cfg.real_world_inference,
        )
    else:
        beam, audit = fail_closed_beam(), {"llm_ok": False, "llm_error": "OPENAI_API_KEY missing", "ts": now_utc()}

    ok, msg = verify_beam(beam, enforce_checksum=True)

    frames: List[LiveSensorFrame] = []
    telemetry: List[LiveTelemetryRecord] = []
    if (cfg.runtime_mode or "").strip().lower() == "live":
        raw = load_live_frames_jsonl(cfg.sensor_feed_path)
        pipe = LiveTelemetryPipeline(
            LiveFilterConfig(
                fir_window=int(cfg.live_fir_window),
                iir_alpha=float(cfg.live_iir_alpha),
                blend_iir=float(cfg.live_blend_iir),
            )
        )
        frames, telemetry = pipe.ingest(raw)
        _ = write_live_telemetry_jsonl(cfg.live_telemetry_path, telemetry)

    roadmap = load_roadmap(cfg.roadmap_path)

    segs, seg_meta = simulate_segments(
        cfg.city,
        cfg.segments,
        hal,
        beam if ok else fail_closed_beam(),
        cfg.polymorph,
        cfg.polymorph_period_s,
        cfg.quantum_mode,
        runtime_mode=cfg.runtime_mode,
        live_frames=frames,
        roadmap=roadmap,
    )
    routes, route_meta = plan_routes(
        cfg.city,
        segs,
        beam if ok else fail_closed_beam(),
        5,
        cfg.polymorph,
        cfg.polymorph_period_s,
        cfg.quantum_mode,
    )

    report: Dict[str, Any] = {
        "city": cfg.city,
        "halocline": cfg.halocline_str,
        "segments": cfg.segments,
        "quantum_mode": cfg.quantum_mode,
        "real_world_inference": cfg.real_world_inference,
        "runtime_mode": cfg.runtime_mode,
        "sensor_feed_path": cfg.sensor_feed_path,
        "roadmap_path": cfg.roadmap_path,
        "live_filter": {
            "fir_window": cfg.live_fir_window,
            "iir_alpha": cfg.live_iir_alpha,
            "blend_iir": cfg.live_blend_iir,
            "telemetry_path": cfg.live_telemetry_path,
            "telemetry_rows": len(list(telemetry or [])),
        },
        "beam_valid": ok,
        "beam_msg": msg,
        "beam_sig": beam_sig(beam),
        "beam_audit": audit,
        "segments_meta": seg_meta,
        "routes_meta": route_meta,
        "routes_top": [dataclasses.asdict(r) for r in routes[:3]],
        "segments_first10": [
            {
                "idx": s.idx,
                "road": s.road,
                "start_gps": s.start_gps,
                "end_gps": s.end_gps,
                "risk": s.risk,
                "flow": s.flow,
                "time": s.time,
                "debris_detected": s.debris_detected,
                "debris_gps": s.debris_gps,
                "debris_severity": s.debris_severity,
                "accident_p_2_min": s.accident_p_2_min,
                "accident_p_5_min": s.accident_p_5_min,
                "accident_p_10_min": s.accident_p_10_min,
                "live_ts_utc": s.live_ts_utc,
            }
            for s in segs[:10]
        ],
    }

    if np is not None:
        try:
            sys = qrag_make(cfg)
            rid = sys.index_beam(
                key=f"beam:{beam_sig(beam)}",
                beam_tokens=beam,
                meta={"city": cfg.city, "halocline": cfg.halocline_str, "ts": now_utc()},
            )
            hits = sys.retrieve("beam similarity", top_k=min(6, int(cfg.qrag_top_k)), kind="beam")
            report["qrag"] = {"indexed_id": rid, "hits": hits, "desc": sys.describe()}
        except Exception as e:
            report["qrag"] = {"error": f"{type(e).__name__}: {e}"}

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


def parse_args() -> Tuple[ScanConfig, bool]:
    p = argparse.ArgumentParser(description="Quantum ColorBeam RoadScanner + QRAG (numpy qsim)")
    p.add_argument("--headless", action="store_true")
    # LIVE is now default; use --simulated to force sim mode
    p.add_argument("--simulated", action="store_true", help="Force simulated runtime mode (no live claims).")
    p.add_argument("--sensor-feed", default="live_sensors.jsonl", help="JSONL file for live sensor frames.")
    p.add_argument("--roadmap", default="", help="Optional roadmap JSON for road names + start/end GPS per segment.")

    p.add_argument("--city", default="greenville_woodruff")
    p.add_argument("--halocline", default="34.84,-82.26,290")
    p.add_argument("--segments", type=int, default=12)
    p.add_argument("--beams-local", type=int, default=8)
    p.add_argument("--polymorph", action="store_true")
    p.add_argument("--polymorph-period", type=int, default=60)
    p.add_argument("--quantum", action="store_true")
    p.add_argument("--realworld", action="store_true", help="Enable plausible real-world priors for test simulation (NOT live).")
    p.add_argument("--resonance-phrase", default="")

    # LIVE filtering + telemetry
    p.add_argument("--live-fir-window", type=int, default=5, help="FIR rolling-mean window per segment (>=1).")
    p.add_argument("--live-iir-alpha", type=float, default=0.35, help="IIR EMA alpha (0..1).")
    p.add_argument("--live-blend-iir", type=float, default=0.6, help="Blend factor (0..1): 1=all IIR, 0=all FIR.")
    p.add_argument("--live-telemetry", default="live_telemetry.jsonl", help="Append LIVE telemetry JSONL here.")

    p.add_argument("--qrag-levels", type=int, default=3)
    p.add_argument("--qrag-depth", type=int, default=2)
    p.add_argument("--qrag-shots", type=int, default=0)
    p.add_argument("--qrag-seed", type=int, default=7)
    p.add_argument("--qrag-no-qutrit", action="store_true")
    p.add_argument("--qrag-topk", type=int, default=6)

    a = p.parse_args()
    cfg = ScanConfig(
        runtime_mode=("simulated" if bool(a.simulated) else "live"),
        sensor_feed_path=str(a.sensor_feed),
        roadmap_path=str(a.roadmap),

        city=str(a.city),
        halocline_str=str(a.halocline),
        segments=max(2, int(a.segments)),
        beams_local=max(1, int(a.beams_local)),
        polymorph=bool(a.polymorph),
        polymorph_period_s=max(10, int(a.polymorph_period)),
        quantum_mode=bool(a.quantum),
        real_world_inference=bool(a.realworld),
        resonance_phrase=str(a.resonance_phrase),

        live_fir_window=max(1, min(60, int(a.live_fir_window))),
        live_iir_alpha=clamp(float(a.live_iir_alpha), 0.0, 1.0),
        live_blend_iir=clamp(float(a.live_blend_iir), 0.0, 1.0),
        live_telemetry_path=str(a.live_telemetry),

        qrag_levels=max(2, min(8, int(a.qrag_levels))),
        qrag_depth=max(0, min(6, int(a.qrag_depth))),
        qrag_shots=max(0, min(20000, int(a.qrag_shots))),
        qrag_seed=int(a.qrag_seed),
        qrag_prefer_qutrit=not bool(a.qrag_no_qutrit),
        qrag_top_k=max(1, min(20, int(a.qrag_topk))),
    )
    return cfg, bool(a.headless)


def main() -> int:
    cfg, head = parse_args()
    if head:
        return asyncio.run(headless(cfg))
    if App is None:
        raise RuntimeError(f"Textual not available: {_TEXTUAL_IMPORT_ERR}")
    RoadScanner().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
