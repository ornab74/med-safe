# main.py
import os, sys, time, json, shutil, hashlib, asyncio, threading, httpx, aiosqlite, getpass, math, random, re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Tuple, Callable, Dict
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

MODEL_REPO = "https://huggingface.co/tensorblock/llama3-small-GGUF/resolve/main/"
MODEL_FILE = "llama3-small-Q3_K_M.gguf"
MODELS_DIR = Path("models")
MODEL_PATH = MODELS_DIR / MODEL_FILE
ENCRYPTED_MODEL = MODEL_PATH.with_suffix(MODEL_PATH.suffix + ".aes")
DB_PATH = Path("chat_history.db.aes")
KEY_PATH = Path(".enc_key")
EXPECTED_HASH = "8e4f4856fb84bafb895f1eb08e6c03e4be613ead2d942f91561aeac742a619aa"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

CSI = "\x1b["
def clear_screen(): sys.stdout.write(CSI + "2J" + CSI + "H")
def show_cursor(): sys.stdout.write(CSI + "?25h")
def color(text, fg=None, bold=False):
    codes=[]
    if fg: codes.append(str(fg))
    if bold: codes.append('1')
    if not codes: return text
    return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"
def boxed(title: str, lines: List[str], width: int = 72):
    top = "┌" + "─"*(width-2) + "┐"
    bot = "└" + "─"*(width-2) + "┘"
    title_line = f"│ {color(title, fg=36, bold=True):{width-4}} │"
    body=[]
    for l in lines:
        if len(l) > width-4:
            chunks = [l[i:i+width-4] for i in range(0,len(l),width-4)]
        else:
            chunks=[l]
        for c in chunks:
            body.append(f"│ {c:{width-4}} │")
    return "\n".join([top, title_line] + body + [bot])

def getch():
    try:
        import tty, termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = os.read(fd, 3)
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except (ImportError, AttributeError, OSError):
        s = input()
        return s[0].encode() if s else b''

def read_menu_choice(num_items:int, prompt="Use ↑↓ arrows or number, Enter to select: ")->int:
    print(prompt)
    try:
        idx = 0
        while True:
            ch = getch()
            if not ch: continue
            if ch == b'\x1b[A' or ch == b'\x1b\x00A':
                idx = (idx - 1) % num_items
            elif ch == b'\x1b[B' or ch == b'\x1b\x00B':
                idx = (idx + 1) % num_items
            elif ch in (b'\r', b'\n', b'\x0d'):
                return idx
            else:
                try:
                    s = ch.decode(errors='ignore')
                    if s.strip().isdigit():
                        n = int(s.strip())
                        if 1 <= n <= num_items:
                            return n-1
                except Exception:
                    pass
            sys.stdout.write(f"\rSelected: {idx+1}/{num_items} ")
            sys.stdout.flush()
    except Exception:
        while True:
            s = input("Enter number: ").strip()
            if s.isdigit():
                n = int(s)
                if 1 <= n <= num_items:
                    return n-1

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
    if KEY_PATH.exists():
        d = KEY_PATH.read_bytes()
        if len(d) >= 48: return d[16:48]
        return d[:32]
    key = AESGCM.generate_key(256)
    KEY_PATH.write_bytes(key)
    print(f"🔑 New random key generated and saved to {KEY_PATH}")
    return key

def derive_key_from_passphrase(pw:str, salt:Optional[bytes]=None) -> Tuple[bytes, bytes]:
    if salt is None: salt = os.urandom(16)
    kdf_der = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    derived = kdf_der.derive(pw.encode("utf-8"))
    return salt, derived

def ensure_key_interactive() -> bytes:
    if KEY_PATH.exists():
        data = KEY_PATH.read_bytes()
        if len(data) >= 48: return data[16:48]
        if len(data) >= 32: return data[:32]
    print("Key not found. Create new key:")
    print("  1) Generate random key (saved raw)")
    print("  2) Derive from passphrase (salt+derived saved)")
    opt = input("Choose (1/2): ").strip()
    if opt == "2":
        pw = getpass.getpass("Enter passphrase: ")
        pw2 = getpass.getpass("Confirm: ")
        if pw != pw2:
            print("Passphrases mismatch. Aborting.")
            sys.exit(1)
        salt, key = derive_key_from_passphrase(pw)
        KEY_PATH.write_bytes(salt + key)
        print(f"Saved salt+derived key to {KEY_PATH}")
        return key
    else:
        key = AESGCM.generate_key(256)
        KEY_PATH.write_bytes(key)
        print(f"Saved random key to {KEY_PATH}")
        return key

def download_model_httpx(url: str, dest: Path, show_progress=True, timeout=None, expected_sha: Optional[str]=None):
    print(f"⬇️  Downloading model from {url}\nTo: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, follow_redirects=True, timeout=timeout) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        h = hashlib.sha256()
        with dest.open("wb") as f:
            for chunk in r.iter_bytes(chunk_size=8192):
                if not chunk: break
                f.write(chunk)
                h.update(chunk)
                done += len(chunk)
                if total and show_progress:
                    pct = done / total * 100
                    bar = int(pct // 2)
                    sys.stdout.write(f"\r[{('#'*bar).ljust(50)}] {pct:5.1f}% ({done//1024}KB/{total//1024}KB)")
                    sys.stdout.flush()
    if show_progress: print("\n✅ Download complete.")
    sha = h.hexdigest()
    print(f"SHA256: {sha}")
    if expected_sha:
        if sha.lower() == expected_sha.lower():
            print(color("SHA256 matches expected.", fg=32, bold=True))
        else:
            print(color(f"SHA256 MISMATCH! expected {expected_sha} got {sha}", fg=31, bold=True))
    return sha

def encrypt_file(src: Path, dest: Path, key: bytes):
    print(f"🔐 Encrypting {src} -> {dest}")
    data = src.read_bytes()
    start = time.time()
    enc = aes_encrypt(data, key)
    dest.write_bytes(enc)
    dur = time.time()-start
    print(f"✅ Encrypted ({len(enc)} bytes) in {dur:.2f}s")

def decrypt_file(src: Path, dest: Path, key: bytes):
    print(f"🔓 Decrypting {src} -> {dest}")
    enc = src.read_bytes()
    data = aes_decrypt(enc, key)
    dest.write_bytes(data)
    print(f"✅ Decrypted ({len(data)} bytes)")

async def init_db(key: bytes):
    if not DB_PATH.exists():
        async with aiosqlite.connect("temp.db") as db:
            await db.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, prompt TEXT, response TEXT)")
            await db.commit()
        with open("temp.db","rb") as f:
            enc = aes_encrypt(f.read(), key)
        DB_PATH.write_bytes(enc)
        os.remove("temp.db")

async def log_interaction(prompt: str, response: str, key: bytes):
    dec = Path("temp.db")
    decrypt_file(DB_PATH, dec, key)
    async with aiosqlite.connect(dec) as db:
        await db.execute("INSERT INTO history (timestamp, prompt, response) VALUES (?, ?, ?)", (time.strftime("%Y-%m-%d %H:%M:%S"), prompt, response))
        await db.commit()
    with dec.open("rb") as f:
        enc = aes_encrypt(f.read(), key)
    DB_PATH.write_bytes(enc)
    dec.unlink()

async def fetch_history(key: bytes, limit:int=20, offset:int=0, search:Optional[str]=None):
    dec = Path("temp.db")
    decrypt_file(DB_PATH, dec, key)
    rows=[]
    async with aiosqlite.connect(dec) as db:
        if search:
            q = f"%{search}%"
            async with db.execute("SELECT id,timestamp,prompt,response FROM history WHERE prompt LIKE ? OR response LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?", (q,q,limit,offset)) as cur:
                async for r in cur: rows.append(r)
        else:
            async with db.execute("SELECT id,timestamp,prompt,response FROM history ORDER BY id DESC LIMIT ? OFFSET ?", (limit,offset)) as cur:
                async for r in cur: rows.append(r)
    with dec.open("rb") as f:
        DB_PATH.write_bytes(aes_encrypt(f.read(), key))
    dec.unlink()
    return rows

def load_llama_model_blocking(model_path: Path) -> Llama:
    return Llama(model_path=str(model_path), n_ctx=2048, n_threads=4)

import os
import sys
import time
from typing import Dict

try:
    import psutil
except Exception:
    psutil = None

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
                    if val > 1000:
                        c = val / 1000.0
                    else:
                        c = float(val)
                    temps.append(c)
                except Exception:
                    continue
        if not temps:
            possible = [
                "/sys/devices/virtual/thermal/thermal_zone0/temp",
                "/sys/class/hwmon/hwmon0/temp1_input",
            ]
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
        missing = [name for name, val in (("cpu", cpu), ("mem", mem), ("load1", load1), ("proc", proc)) if val is None]
        print(f"[FATAL] Unable to obtain core system metrics: missing {missing}")
        sys.exit(2)
    cpu = float(max(0.0, min(1.0, cpu)))
    mem = float(max(0.0, min(1.0, mem)))
    load1 = float(max(0.0, min(1.0, load1)))
    proc = float(max(0.0, min(1.0, proc)))
    temp = float(max(0.0, min(1.0, temp))) if temp is not None else 0.0
    return {"cpu": cpu, "mem": mem, "load1": load1, "temp": temp, "proc": proc}

def metrics_to_rgb(metrics: dict) -> Tuple[float,float,float]:
    cpu = metrics.get("cpu",0.1); mem = metrics.get("mem",0.1); temp = metrics.get("temp",0.1); load1 = metrics.get("load1",0.0); proc = metrics.get("proc",0.0)
    r = cpu * (1.0 + load1); g = mem * (1.0 + proc); b = temp * (0.5 + cpu * 0.5)
    maxi = max(r,g,b,1.0); r,g,b = r/maxi,g/maxi,b/maxi
    return (float(max(0.0,min(1.0,r))), float(max(0.0,min(1.0,g))), float(max(0.0,min(1.0,b))))

def pennylane_entropic_score(rgb: Tuple[float,float,float], shots: int = 256) -> float:
    if qml is None or pnp is None:
        r,g,b = rgb
        seed = int((r*255)<<16 | (g*255)<<8 | (b*255))
        random.seed(seed)
        base = (0.3*r + 0.4*g + 0.3*b)
        noise = (random.random()-0.5)*0.08
        return max(0.0, min(1.0, base + noise))
    dev = qml.device("default.qubit", wires=2, shots=shots)
    @qml.qnode(dev)
    def circuit(a,b,c):
        qml.RX(a * math.pi, wires=0)
        qml.RY(b * math.pi, wires=1)
        qml.CNOT(wires=[0,1])
        qml.RZ(c * math.pi, wires=1)
        qml.RX((a + b) * math.pi / 2, wires=0)
        qml.RY((b + c) * math.pi / 2, wires=1)
        return qml.expval(qml.PauliZ(0)), qml.expval(qml.PauliZ(1))
    a,b,c = float(rgb[0]), float(rgb[1]), float(rgb[2])
    try:
        ev0,ev1 = circuit(a,b,c)
        combined = ((ev0+1.0)/2.0 * 0.6 + (ev1+1.0)/2.0 * 0.4)
        score = 1.0 / (1.0 + math.exp(-6.0*(combined - 0.5)))
        return float(max(0.0,min(1.0,score)))
    except Exception:
        return float(0.5 * (a+b+c) / 3.0)

def entropic_to_modifier(score: float) -> float:
    return (score - 0.5) * 0.4

def entropic_summary_text(score: float) -> str:
    if score >= 0.75: level = "high"
    elif score >= 0.45: level = "medium"
    else: level = "low"
    return f"entropic_score={score:.3f} (level={level})"

def _simple_tokenize(text: str) -> List[str]:
    return [t for t in re.findall(r"[A-Za-z0-9_\-]+", text.lower())]

def punkd_analyze(prompt_text: str, top_n: int = 12) -> Dict[str,float]:
    toks = _simple_tokenize(prompt_text)
    freq={}
    for t in toks: freq[t]=freq.get(t,0)+1
    hazard_boost = {"ice":2.0,"wet":1.8,"snow":2.0,"flood":2.0,"construction":1.8,"pedestrian":1.8,"debris":1.8,"animal":1.5,"stall":1.4,"fog":1.6}
    scored={}
    for t,c in freq.items():
        boost = hazard_boost.get(t,1.0)
        scored[t]=c*boost
    items = sorted(scored.items(), key=lambda x:-x[1])[:top_n]
    if not items: return {}
    maxv = items[0][1]
    return {k: float(v/maxv) for k,v in items}

def punkd_apply(prompt_text: str, token_weights: Dict[str,float], profile: str = "balanced") -> Tuple[str,float]:
    if not token_weights: return prompt_text, 1.0
    mean_weight = sum(token_weights.values())/len(token_weights)
    profile_map = {"conservative": 0.6, "balanced": 1.0, "aggressive": 1.4}
    base = profile_map.get(profile, 1.0)
    multiplier = 1.0 + (mean_weight - 0.5) * 0.8 * (base if base>1.0 else 1.0)
    multiplier = max(0.6, min(1.8, multiplier))
    sorted_tokens = sorted(token_weights.items(), key=lambda x:-x[1])[:6]
    markers = " ".join([f"<ATTN:{t}:{round(w,2)}>" for t,w in sorted_tokens])
    patched = prompt_text + "\n\n[PUNKD_MARKERS] " + markers
    return patched, multiplier

def chunked_generate(llm: Llama, prompt: str, max_total_tokens: int = 256, chunk_tokens: int = 64, base_temperature: float = 0.2, punkd_profile: str = "balanced", streaming_callback: Optional[Callable[[str], None]] = None) -> str:
    assembled = ""
    cur_prompt = prompt
    token_weights = punkd_analyze(prompt, top_n=16)
    iterations = max(1, (max_total_tokens + chunk_tokens - 1)//chunk_tokens)
    prev_tail = ""
    for i in range(iterations):
        patched_prompt, mult = punkd_apply(cur_prompt, token_weights, profile=punkd_profile)
        temp = max(0.01, min(2.0, base_temperature * mult))
        out = llm(patched_prompt, max_tokens=chunk_tokens, temperature=temp)
        text = ""
        if isinstance(out, dict):
            try: text = out.get("choices",[{"text":""}])[0].get("text","")
            except Exception:
                text = out.get("text","") if isinstance(out, dict) else ""
        else:
            try: text = str(out)
            except Exception: text = ""
        text = (text or "").strip()
        if not text: break
        overlap = 0
        max_ol = min(30, len(prev_tail), len(text))
        for olen in range(max_ol, 0, -1):
            if prev_tail.endswith(text[:olen]):
                overlap = olen
                break
        append_text = text[overlap:] if overlap else text
        assembled += append_text
        prev_tail = assembled[-120:] if len(assembled)>120 else assembled
        if streaming_callback: streaming_callback(append_text)
        if assembled.strip().endswith(("Low","Medium","High")): break
        if len(text.split()) < max(4, chunk_tokens//8): break
        cur_prompt = prompt + "\n\nAssistant so far:\n" + assembled + "\n\nContinue:"
    return assembled.strip()

def build_road_scanner_prompt(data: dict, include_system_entropy: bool = True) -> str:
    entropy_text = "entropic_score=unknown"
    if include_system_entropy:
        metrics = collect_system_metrics()
        rgb = metrics_to_rgb(metrics)
        score = pennylane_entropic_score(rgb)
        entropy_text = entropic_summary_text(score)
        metrics_line = "sys_metrics: cpu={cpu:.2f},mem={mem:.2f},load={load1:.2f},temp={temp:.2f},proc={proc:.2f}".format(cpu=metrics.get("cpu",0.0), mem=metrics.get("mem",0.0), load1=metrics.get("load1",0.0), temp=metrics.get("temp",0.0), proc=metrics.get("proc_count",0.0))
    else:
        metrics_line = "sys_metrics: disabled"
    tpl = (
f"You are a Hypertime Nanobot specialized Road Risk Classification AI trained to evaluate real-world driving scenes.\n"
f"Analyze and Triple Check for validating accuracy the environmental and sensor data and determine the overall road risk level.\n"
f"Your reply must be only one word: Low, Medium, or High.\n\n"
f"[tuning]\n"
f"Scene details:\n"
f"Location: {data.get('location','unspecified location')}\n"
f"Road type: {data.get('road_type','unknown')}\n"
f"Weather: {data.get('weather','unknown')}\n"
f"Traffic: {data.get('traffic','unknown')}\n"
f"Obstacles: {data.get('obstacles','none')}\n"
f"Sensor notes: {data.get('sensor_notes','none')}\n"
f"{metrics_line}\n"
f"Quantum State: {entropy_text}\n"
f"[/tuning]\n\n"
f"Follow these strict rules when forming your decision:\n"
f"- Think through all scene factors internally but do not show reasoning.\n"
f"- Evaluate surface, visibility, weather, traffic, and obstacles holistically.\n"
f"- Optionally use the system entropic signal to bias your internal confidence slightly.\n"
f"- Choose only one risk level that best fits the entire situation.\n"
f"- Output exactly one word, with no punctuation or labels.\n"
f"- The valid outputs are only: Low, Medium, High.\n\n"
f"[action]\n"
f"1) Normalize sensor inputs to comparable scales.\n"
f"3) Map environmental risk cues -> discrete label using conservative thresholds.\n"
f"4) If sensor integrity anomalies are detected, bias toward higher risk.\n"
f"5) PUNKD: detect key tokens and locally adjust attention/temperature slightly to focus decisions.\n"
f"6) Do not output internal reasoning or diagnostics; only return the single-word label.\n"
f"[/action]\n\n"
f"[replytemplate]\nLow | Medium | High\n[/replytemplate]"
    )
    return tpl

def header(status:dict):
    s = f" Secure LLM CLI — Model: {'loaded' if status.get('model_loaded') else 'none'} | Key: {'present' if status.get('key') else 'missing'} "
    print(color(s.center(80,'─'), fg=35, bold=True))

def model_manager(state:dict):
    while True:
        clear_screen(); header(state)
        lines=["1) Download model from remote repo (httpx)","2) Verify plaintext model hash (compute SHA256)","3) Encrypt plaintext model -> .aes","4) Decrypt .aes -> plaintext (temporary)","5) Delete plaintext model","6) Back"]
        print(boxed("Model Manager", lines))
        choice = input("Choose (1-6): ").strip()
        if choice=="1":
            if MODEL_PATH.exists():
                if input("Plaintext model exists; overwrite? (y/N): ").strip().lower()!='y': continue
            try:
                url = MODEL_REPO + MODEL_FILE
                sha = download_model_httpx(url, MODEL_PATH, show_progress=True, timeout=None, expected_sha=EXPECTED_HASH)
                print(f"Downloaded to {MODEL_PATH}")
                print(f"Computed SHA256: {sha}")
                if input("Encrypt downloaded model with current key now? (Y/n): ").strip().lower()!='n':
                    encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, state['key'])
                    print(f"Encrypted -> {ENCRYPTED_MODEL}")
                    if input("Remove plaintext model? (Y/n): ").strip().lower()!='n':
                        MODEL_PATH.unlink(); print("Plaintext removed.")
            except Exception as e:
                print(f"Download failed: {e}")
            input("Enter to continue...")
        elif choice=="2":
            if not MODEL_PATH.exists(): print("No plaintext model found.")
            else: print(f"SHA256: {sha256_file(MODEL_PATH)}")
            input("Enter to continue...")
        elif choice=="3":
            if not MODEL_PATH.exists(): print("No plaintext model to encrypt."); input("Enter..."); continue
            encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, state['key'])
            if input("Remove plaintext? (Y/n): ").strip().lower()!='n':
                MODEL_PATH.unlink(); print("Removed plaintext.")
            input("Enter...")
        elif choice=="4":
            if not ENCRYPTED_MODEL.exists(): print("No .aes model present.")
            else: decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, state['key'])
            input("Enter...")
        elif choice=="5":
            if MODEL_PATH.exists():
                if input(f"Delete {MODEL_PATH}? (y/N): ").strip().lower()=="y": MODEL_PATH.unlink(); print("Deleted.")
            else: print("No plaintext model.")
            input("Enter...")
        elif choice=="6": return
        else: print("Invalid.")

async def chat_session(state:dict):
    if not ENCRYPTED_MODEL.exists(): print("No encrypted model found. Please download & encrypt first."); input("Enter..."); return
    decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, state['key'])
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as ex:
        try:
            print("Loading model..."); llm = await loop.run_in_executor(ex, load_llama_model_blocking, MODEL_PATH)
        except Exception as e:
            print(f"Failed to load: {e}")
            if MODEL_PATH.exists():
                try: encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, state['key']); MODEL_PATH.unlink()
                except Exception: pass
            input("Enter..."); return
        state['model_loaded']=True
        try:
            await init_db(state['key'])
            print("Type /exit to return, /history to show last 10 messages.")
            while True:
                prompt = input("\nYou> ").strip()
                if not prompt: continue
                if prompt in ("/exit","exit","quit"): break
                if prompt=="/history":
                    rows = await fetch_history(state['key'], limit=10)
                    for r in rows: print(f"[{r[0]}] {r[1]}\nQ: {r[2]}\nA: {r[3]}\n{'-'*30}")
                    continue
                def gen(p):
                    out = llm(p, max_tokens=256, temperature=0.7)
                    text = ""
                    if isinstance(out, dict):
                        try: text = out.get("choices",[{"text":""}])[0].get("text","")
                        except Exception: text = out.get("text","")
                    else: text = str(out)
                    text = (text or "").strip()
                    text = text.replace("You are a helpful AI assistant named SmolLM, trained by Hugging Face","").strip()
                    return text
                print("🤖 Thinking...")
                result = await loop.run_in_executor(ex, gen, prompt)
                print("\nModel:\n"+result+"\n")
                await log_interaction(prompt, result, state['key'])
        finally:
            try: del llm
            except Exception: pass
            print("Re-encrypting model and removing plaintext...")
            try: encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, state['key']); MODEL_PATH.unlink(); state['model_loaded']=False
            except Exception as e: print(f"Cleanup failed: {e}")
            input("Enter...")

async def road_scanner_flow(state:dict):
    if not ENCRYPTED_MODEL.exists(): print("No encrypted model found."); input("Enter..."); return
    data={}
    clear_screen(); header(state)
    print(boxed("Road Scanner - Step 1/6", ["Leave blank for defaults"]))
    data['location'] = input("Location (e.g., 'I-95 NB mile 12'): ").strip() or "unspecified location"
    data['road_type'] = input("Road type (highway/urban/residential): ").strip() or "highway"
    data['weather'] = input("Weather/visibility: ").strip() or "clear"
    data['traffic'] = input("Traffic density (low/med/high): ").strip() or "low"
    data['obstacles'] = input("Reported obstacles: ").strip() or "none"
    data['sensor_notes'] = input("Sensor notes: ").strip() or "none"
    print("\nGeneration options:\n1) Chunked generation + punkd (recommended)\n2) Chunked only\n3) Direct single-call generation")
    gen_choice = input("Choose (1-3) [1]: ").strip() or "1"
    prompt = build_road_scanner_prompt(data, include_system_entropy=True)
    decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, state['key'])
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as ex:
        try:
            llm = await loop.run_in_executor(ex, load_llama_model_blocking, MODEL_PATH)
        except Exception as e:
            print(f"Model load failed: {e}")
            if MODEL_PATH.exists():
                try: encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, state['key']); MODEL_PATH.unlink()
                except Exception: pass
            input("Enter..."); return
        def gen_direct(p):
            out = llm(p, max_tokens=128, temperature=0.2)
            if isinstance(out, dict):
                try: text = out.get("choices",[{"text":""}])[0].get("text","")
                except Exception: text = out.get("text","")
            else: text = str(out)
            text = (text or "").strip()
            return text.replace("You are a helpful AI assistant named SmolLM, trained by Hugging Face","").strip()
        if gen_choice == "3":
            print("Scanning (single-call)...")
            result = await loop.run_in_executor(ex, gen_direct, prompt)
        else:
            punkd_profile = "balanced" if gen_choice=="1" else "conservative"
            print("Scanning with chunked generation (this may take a moment)...")
            def run_chunked():
                return chunked_generate(llm=llm, prompt=prompt, max_total_tokens=256, chunk_tokens=64, base_temperature=0.18, punkd_profile=punkd_profile, streaming_callback=None)
            result = await loop.run_in_executor(ex, run_chunked)
        text = (result or "").strip().replace("You are a helpful AI assistant named SmolLM, trained by Hugging Face","")
        candidate = text.split()
        label = candidate[0].capitalize() if candidate else ""
        if label not in ("Low","Medium","High"):
            lowered = text.lower()
            if "low" in lowered: label = "Low"
            elif "medium" in lowered: label = "Medium"
            elif "high" in lowered: label = "High"
            else: label = "Medium"
        print("\n--- Road Scanner Result ---\n")
        if label == "Low": print(color(label, fg=32, bold=True))
        elif label == "Medium": print(color(label, fg=33, bold=True))
        else: print(color(label, fg=31, bold=True))
        print("\nOptions: 1) Re-run with edits  2) Export to JSON  3) Save & return  4) Cancel")
        ch = input("Choose (1-4): ").strip()
        if ch=="1":
            print("Re-run: editing fields. Press Enter to keep current value.")
            for k in list(data.keys()):
                v = input(f"{k} [{data[k]}]: ").strip()
                if v: data[k]=v
            prompt = build_road_scanner_prompt(data, include_system_entropy=True)
            print("Re-scanning...")
            if gen_choice == "3": result = await loop.run_in_executor(ex, gen_direct, prompt)
            else:
                def run_chunked2(): return chunked_generate(llm=llm, prompt=prompt, max_total_tokens=256, chunk_tokens=64, base_temperature=0.18, punkd_profile=punkd_profile, streaming_callback=None)
                result = await loop.run_in_executor(ex, run_chunked2)
            print("\n"+(result or ""))
        if ch in ("2","3"):
            try: await init_db(state['key']); await log_interaction("ROAD_SCANNER_PROMPT:\n"+prompt, "ROAD_SCANNER_RESULT:\n"+label, state['key'])
            except Exception as e: print(f"Failed to log: {e}")
        if ch=="2":
            outp = {"input": data, "prompt": prompt, "result": label, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
            fn = input("Filename to save JSON (default road_scan.json): ").strip() or "road_scan.json"
            Path(fn).write_text(json.dumps(outp, indent=2)); print(f"Saved {fn}")
        try: del llm
        except Exception: pass
        print("Re-encrypting model and removing plaintext...")
        try: encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, state['key']); MODEL_PATH.unlink()
        except Exception as e: print(f"Cleanup error: {e}")
        input("Enter to return...")

async def db_viewer_flow(state:dict):
    if not DB_PATH.exists(): print("No DB found."); input("Enter..."); return
    page=0; per_page=10; search=None
    while True:
        rows = await fetch_history(state['key'], limit=per_page, offset=page*per_page, search=search)
        clear_screen(); header(state)
        title = f"History (page {page+1})"
        print(boxed(title, [f"Search: {search or '(none)'}", "Commands: n=next p=prev s=search q=quit"]))
        if not rows: print("No rows on this page.")
        else:
            for r in rows: print(f"[{r[0]}] {r[1]}\nQ: {r[2]}\nA: {r[3]}\n" + "-"*60)
        cmd = input("cmd (n/p/s/q): ").strip().lower()
        if cmd=="n": page +=1
        elif cmd=="p" and page>0: page -=1
        elif cmd=="s": search = input("Enter search keyword (empty to clear): ").strip() or None; page = 0
        else: break

def rekey_flow(state:dict):
    print("Rekey / Rotate Key")
    if KEY_PATH.exists(): print(f"Current key file: {KEY_PATH}")
    else: print("No existing key file (creating new).")
    choice = input("1) New random key  2) Passphrase-derived  3) Cancel\nChoose: ").strip()
    if choice not in ("1","2"): print("Canceled."); input("Enter..."); return
    old_key = state['key']
    tmp_model = MODELS_DIR / (MODEL_FILE + ".tmp"); tmp_db = Path("temp.db")
    try:
        if ENCRYPTED_MODEL.exists():
            try: decrypt_file(ENCRYPTED_MODEL, tmp_model, old_key)
            except Exception as e: print(f"Failed to decrypt model with current key: {e}"); safe_cleanup([tmp_model,tmp_db]); input("Enter..."); return
        if DB_PATH.exists():
            try: decrypt_file(DB_PATH, tmp_db, old_key)
            except Exception as e: print(f"Failed to decrypt DB with current key: {e}"); safe_cleanup([tmp_model,tmp_db]); input("Enter..."); return
    except Exception as e:
        print(f"Unexpected: {e}"); safe_cleanup([tmp_model,tmp_db]); input("Enter..."); return
    if choice=="1":
        new_key = AESGCM.generate_key(256); KEY_PATH.write_bytes(new_key); print("New random key generated and saved.")
    else:
        pw = getpass.getpass("Enter new passphrase: "); pw2 = getpass.getpass("Confirm: ")
        if pw!=pw2: print("Mismatch."); safe_cleanup([tmp_model,tmp_db]); input("Enter..."); return
        salt, derived = derive_key_from_passphrase(pw); KEY_PATH.write_bytes(salt + derived); new_key = derived; print("New passphrase-derived key saved (salt+derived).")
    try:
        if tmp_model.exists():
            old_h = sha256_file(tmp_model)
            encrypt_file(tmp_model, ENCRYPTED_MODEL, new_key)
            new_h_enc = sha256_file(ENCRYPTED_MODEL)
            print(f"Model plaintext SHA256: {old_h}")
            print(f"Encrypted model SHA256: {new_h_enc}")
        if tmp_db.exists():
            old_db_h = sha256_file(tmp_db)
            with tmp_db.open("rb") as f: DB_PATH.write_bytes(aes_encrypt(f.read(), new_key))
            new_db_h = sha256_file(DB_PATH)
            print(f"DB plaintext SHA256: {old_db_h}")
            print(f"Encrypted DB SHA256: {new_db_h}")
    except Exception as e: print(f"Error during re-encryption: {e}")
    finally:
        safe_cleanup([tmp_model,tmp_db])
        state['key'] = KEY_PATH.read_bytes()[16:48] if KEY_PATH.exists() and len(KEY_PATH.read_bytes())>=48 else KEY_PATH.read_bytes()[:32]
        print("Rekey attempt finished. Verify files manually."); input("Enter...")

def safe_cleanup(paths:List[Path]):
    for p in paths:
        try:
            if p.exists(): p.unlink()
        except Exception: pass

def main_menu_loop(state:dict):
    options = ["Model Manager","Chat with model","Road Scanner","View chat history","Rekey / Rotate key","Exit"]
    while True:
        clear_screen(); header(state); print()
        print(boxed("Main Menu", [f"{i+1}) {opt}" for i,opt in enumerate(options)]))
        idx = read_menu_choice(len(options)); choice = options[idx]
        if choice == "Model Manager": model_manager(state)
        elif choice == "Chat with model": asyncio.run(chat_session(state))
        elif choice == "Road Scanner": asyncio.run(road_scanner_flow(state))
        elif choice == "View chat history": asyncio.run(db_viewer_flow(state))
        elif choice == "Rekey / Rotate key": rekey_flow(state)
        elif choice == "Exit": print("Goodbye."); return

def main():
    try: key = ensure_key_interactive()
    except Exception: key = get_or_create_key()
    state = {"key": key, "model_loaded": False}
    try:
        asyncio.run(init_db(state['key']))
    except Exception: pass
    try:
        main_menu_loop(state)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        show_cursor()

# ---------------------------------------------------------------------------
# MOBILE / KIVYMD HELPERS (non-destructive wrappers around your backend)
# ---------------------------------------------------------------------------

async def mobile_ensure_init() -> bytes:
    """
    Mobile-friendly init: ensure key + DB, no stdin / getpass prompts.
    """
    key = get_or_create_key()
    try:
        await init_db(key)
    except Exception:
        pass
    return key

async def mobile_run_chat(prompt: str) -> str:
    """
    Run a single chat turn using your llama model, log to encrypted DB.
    """
    key = await mobile_ensure_init()

    # Decrypt model if encrypted version exists
    if ENCRYPTED_MODEL.exists() and not MODEL_PATH.exists():
        decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, key)

    # If neither plaintext nor encrypted exist, bail
    if not MODEL_PATH.exists() and not ENCRYPTED_MODEL.exists():
        return "[Model not found. Place or download the GGUF model on device.]"

    if not MODEL_PATH.exists() and ENCRYPTED_MODEL.exists():
        decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, key)

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as ex:
        try:
            llm = await loop.run_in_executor(ex, load_llama_model_blocking, MODEL_PATH)
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

        # Re-encrypt model if encrypted version is being used
        if ENCRYPTED_MODEL.exists():
            try:
                encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, key)
                if MODEL_PATH.exists():
                    MODEL_PATH.unlink()
            except Exception:
                pass

    return result

async def mobile_run_road_scan(data: dict) -> Tuple[str, str]:
    """
    Run the Hypertime Nanobot Road Scanner with same prompt + quantum logic.
    Returns (label, raw_model_text).
    """
    key = await mobile_ensure_init()
    prompt = build_road_scanner_prompt(data, include_system_entropy=True)

    if ENCRYPTED_MODEL.exists() and not MODEL_PATH.exists():
        decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, key)

    if not MODEL_PATH.exists() and not ENCRYPTED_MODEL.exists():
        return "[Model not found]", "[Model not found. Place or download the GGUF model on device.]"

    if not MODEL_PATH.exists() and ENCRYPTED_MODEL.exists():
        decrypt_file(ENCRYPTED_MODEL, MODEL_PATH, key)

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as ex:
        try:
            llm = await loop.run_in_executor(ex, load_llama_model_blocking, MODEL_PATH)
        except Exception as e:
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
            await log_interaction("ROAD_SCANNER_PROMPT:\n"+prompt, "ROAD_SCANNER_RESULT:\n"+label, key)
        except Exception:
            pass

        try:
            del llm
        except Exception:
            pass

        if ENCRYPTED_MODEL.exists():
            try:
                encrypt_file(MODEL_PATH, ENCRYPTED_MODEL, key)
                if MODEL_PATH.exists():
                    MODEL_PATH.unlink()
            except Exception:
                pass

    return label, text

# ---------------------------------------------------------------------------
# KIVYMD UI
# ---------------------------------------------------------------------------
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.core.window import Window

from kivymd.app import MDApp

# Optional: set a sane default window size when running on desktop
if hasattr(Window, "size"):
    Window.size = (400, 700)

KV = """
MDScreen:
    MDBoxLayout:
        orientation: "vertical"

        MDToolbar:
            title: "Secure LLM Road Scanner"
            elevation: 10
            left_action_items: [["chat", lambda x: app.switch_screen("chat")]]
            right_action_items: [["road", lambda x: app.switch_screen("road")]]

        MDLabel:
            id: status_label
            text: ""
            size_hint_y: None
            height: "24dp"
            halign: "center"

        MDScreenManager:
            id: screen_manager

            MDScreen:
                name: "chat"

                MDBoxLayout:
                    orientation: "vertical"
                    padding: "8dp"
                    spacing: "8dp"

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

                    MDRaisedButton:
                        text: "Send"
                        size_hint_x: 1
                        on_release: app.on_chat_send()

            MDScreen:
                name: "road"

                MDBoxLayout:
                    orientation: "vertical"
                    padding: "8dp"
                    spacing: "8dp"

                    MDTextField:
                        id: loc_field
                        hint_text: "Location (e.g., 'I-95 NB mile 12')"

                    MDTextField:
                        id: road_type_field
                        hint_text: "Road type (highway/urban/residential)"

                    MDTextField:
                        id: weather_field
                        hint_text: "Weather/visibility"

                    MDTextField:
                        id: traffic_field
                        hint_text: "Traffic density (low/med/high)"

                    MDTextField:
                        id: obstacles_field
                        hint_text: "Reported obstacles"

                    MDTextField:
                        id: sensor_notes_field
                        hint_text: "Sensor notes"

                    MDRaisedButton:
                        text: "Scan risk"
                        size_hint_x: 1
                        on_release: app.on_scan()

                    MDLabel:
                        id: scan_result
                        text: ""
                        halign: "center"
"""

class SecureLLMApp(MDApp):
    chat_history_text = ""

    def build(self):
        self.title = "Secure LLM Road Scanner"
        self.theme_cls.primary_palette = "Blue"
        return Builder.load_string(KV)

    # -----------------------------
    # Screen switching
    # -----------------------------
    def switch_screen(self, name: str):
        sm = self.root.ids.screen_manager
        sm.current = name

    # -----------------------------
    # Status helpers
    # -----------------------------
    def set_status(self, text: str):
        self.root.ids.status_label.text = text

    # -----------------------------
    # Chat logic
    # -----------------------------
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

    # -----------------------------
    # Road scanner logic
    # -----------------------------
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
        self.set_status("Scanning road risk...")
        threading.Thread(target=self._scan_worker, args=(data,), daemon=True).start()

    def _scan_worker(self, data: dict):
        try:
            label, raw = asyncio.run(mobile_run_road_scan(data))
        except Exception as e:
            label, raw = "[Error]", f"[Error: {e}]"
        Clock.schedule_once(lambda dt: self._scan_finish(label, raw))

    def _scan_finish(self, label: str, raw: str):
        road_screen = self.root.ids.screen_manager.get_screen("road")
        if label == "Low":
            disp = f"[LOW] {label}"
        elif label == "Medium":
            disp = f"[MEDIUM] {label}"
        elif label == "High":
            disp = f"[HIGH] {label}"
        else:
            disp = label
        road_screen.ids.scan_result.text = disp
        self.set_status("")

# ---------------------------------------------------------------------------
# ANDROID / KIVY ENTRYPOINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    SecureLLMApp().run()
