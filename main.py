#!/usr/bin/env python3
import os,time,json,hashlib,asyncio,threading,httpx,aiosqlite,math,random,re
import numpy as np
from pathlib import Path
from typing import Dict,Tuple,Callable,Optional
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from llama_cpp import Llama

try:import psutil
except:psutil=None
try:
    import pennylane as qml
    from pennylane import numpy as pnp
except:qml=pnp=None

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.screenmanager import ScreenManager,Screen
from kivy.clock import Clock
from kivy.utils import platform
from kivy.core.window import Window
from kivy.animation import Animation
from kivy.graphics import Color,Ellipse,Rotate,PushMatrix,PopMatrix
from kivymd.app import MDApp
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.label import MDLabel
from kivymd.uix.spinner import MDSpinner

if platform=="android":
    from jnius import autoclass,cast
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    LocationManager = autoclass('android.location.LocationManager')
    Context = autoclass('android.content.Context')
    LocationListener = autoclass('android.location.LocationListener')
import os
import ctypes

# Load real Python 3.14
lib = ctypes.CDLL("data/python314/lib/libpython3.14.so")
lib.Py_Initialize()

# Optional: run a test
lib.PyRun_SimpleString("import sys; print('Python', sys.version)".encode())
# ────────────────────────────── CONSTANTS ──────────────────────────────
MODEL_REPO="https://huggingface.co/tensorblock/llama3-small-GGUF/resolve/main/"
MODEL_FILE="llama3-small-Q3_K_M.gguf"
MODELS_DIR=Path("models")
MODEL_PATH=MODELS_DIR/MODEL_FILE
ENCRYPTED_MODEL=MODEL_PATH.with_suffix(".aes")
DB_PATH=Path("chat_history.db.aes")
KEY_PATH=Path(".enc_key")
EXPECTED_HASH="8e4f4856fb84bafb895f1eb08e6c03e4be613ead2d942f91561aeac742a619aa"
MODELS_DIR.mkdir(parents=True,exist_ok=True)

# ────────────────────────────── ENCRYPTION & DB ──────────────────────────────
def aes_encrypt(d:bytes,k:bytes)->bytes:AESGCM(k);n=os.urandom(12);return n+AESGCM(k).encrypt(n,d,None)
def aes_decrypt(d:bytes,k:bytes):n,c=d[:12],d[12:];return AESGCM(k).decrypt(n,c,None)
def get_key()->bytes:
    if not KEY_PATH.exists():KEY_PATH.write_bytes(AESGCM.generate_key(256))
    return KEY_PATH.read_bytes()[:32]
def encrypt_file(s:Path,d:Path,k:bytes):d.write_bytes(aes_encrypt(s.read_bytes(),k))
def decrypt_file(s:Path,d:Path,k:bytes):d.write_bytes(aes_decrypt(s.read_bytes(),k))

async def init_db(k:bytes):
    if DB_PATH.exists():return
    async with aiosqlite.connect(":memory:")as db:
        await db.execute("CREATE TABLE h(id INTEGER PRIMARY KEY,ts TEXT,p TEXT,r TEXT)")
        await db.commit()
async def log_interaction(p:str,r:str,k:bytes):
    t=Path("tmp.db")
    if DB_PATH.exists():decrypt_file(DB_PATH,t,k)
    else:t.touch()
    async with aiosqlite.connect(t)as db:
        await db.execute("INSERT INTO h(ts,p,r)VALUES(?,?,?)",(time.strftime("%Y-%m-%d %H:%M:%S"),p,r))
        await db.commit()
    encrypt_file(t,DB_PATH,k);t.unlink()

# ────────────────────────────── SYSTEM METRICS ──────────────────────────────
def collect_system_metrics()->Dict[str,float]:
    c=m=l=t=p=None
    if psutil:
        try:c=psutil.cpu_percent(0.1)/100;m=psutil.virtual_memory().percent/100
        except:pass
    return {"cpu":float(c or 0.3),"mem":float(m or 0.4),"load1":0.2,"temp":0.5,"proc":0.1}

def metrics_to_rgb(m:dict)->Tuple[float,float,float]:
    r=m["cpu"]*2.2;g=m["mem"]*1.9;b=m["temp"]*1.5
    mx=max(r,g,b,1.0);return(r/mx,g/mx,b/mx)

def pennylane_entropic_score(rgb:Tuple[float,float,float],shots:int=256)->float:
    if qml is None:return sum(rgb)/3+random.random()*0.15-0.075
    dev=qml.device("default.qubit",wires=2,shots=shots)
    @qml.qnode(dev)
    def circuit(a,b,c):
        qml.RX(a*math.pi,wires=0);qml.RY(b*math.pi,wires=1);qml.CNOT(wires=[0,1])
        qml.RZ(c*math.pi,wires=1);qml.RX((a+b+c)*math.pi/3,wires=0)
        return qml.expval(qml.PauliZ(0)),qml.expval(qml.PauliZ(1))
    try:
        e0,e1=circuit(*rgb)
        s=1.0/(1.0+math.exp(-9.0*(((e0+1)/2*0.65+(e1+1)/2*0.35)-0.5)))
        return float(s)
    except:return 0.5

def entropic_summary_text(score:float)->str:
    if score>=0.78:return f"CHAOS RESONANCE {score:.3f}"
    if score>=0.55:return f"TURBULENT FIELD {score:.3f}"
    return f"STABLE MANIFOLD {score:.3f}"

# ────────────────────────────── PUNKD & CHUNKED GENERATION ──────────────────────────────
def punkd_analyze(text:str,top_n:int=16)->Dict[str,float]:
    toks=re.findall(r"[a-zA-Z0-9_]+",text.lower())
    freq={};[freq.__setitem__(t,freq.get(t,0)+1)for t in toks]
    boost={"ice":2.8,"wet":2.5,"snow":2.9,"fog":2.3,"flood":3.0,"construction":2.2,"debris":2.4,"animal":2.1,"blackice":4.0,"hydroplane":3.5}
    scored={t:c*boost.get(t,1.0)for t,c in freq.items()}
    top=sorted(scored.items(),key=lambda x:-x[1])[:top_n]
    if not top:return {}
    mx=top[0][1]
    return {k:float(v/mx)for k,v in top}

def punkd_apply(prompt:str,weights:Dict[str,float],profile:str="balanced")->Tuple[str,float]:
    if not weights:return prompt,1.0
    mean=sum(weights.values())/len(weights)
    mul_map={"conservative":0.7,"balanced":1.0,"aggressive":1.6}
    mul=mul_map.get(profile,1.0)
    adj=1.0+(mean-0.5)*1.2*mul
    adj=max(0.6,min(2.2,adj))
    markers=" ".join([f"<HAZ:{k}:{v:.2f}>"for k,v in sorted(weights.items(),key=lambda x:-x[1])[:8]])
    return prompt+f"\n\n[PUNKD HAZARD BOOST] {markers}",adj

def chunked_generate(llm:Llama,prompt:str,max_total_tokens:int=256,chunk_tokens:int=64,
                    base_temperature:float=0.18,punkd_profile:str="balanced",
                    streaming_callback:Optional[Callable[[str],None]]=None)->str:
    assembled="";cur_prompt=prompt
    token_weights=punkd_analyze(prompt,top_n=16)
    iterations=max(1,(max_total_tokens+chunk_tokens-1)//chunk_tokens)
    prev_tail=""
    for i in range(iterations):
        patched_prompt,mult=punkd_apply(cur_prompt,token_weights,profile=punkd_profile)
        temp=max(0.01,min(2.0,base_temperature*mult))
        out=llm(patched_prompt,max_tokens=chunk_tokens,temperature=temp,stop=["Low","Medium","High","\n","\r"])
        text=""
        if isinstance(out,dict):
            try:text=out.get("choices",[{}])[0].get("text","")
            except:text=out.get("text","")if isinstance(out,dict)else""
        else:text=str(out)
        text=(text or"").strip()
        if not text:break
        overlap=0
        max_ol=min(30,len(prev_tail),len(text))
        for olen in range(max_ol,0,-1):
            if prev_tail.endswith(text[:olen]):
                overlap=olen;break
        append_text=text[overlap:]if overlap else text
        assembled+=append_text
        prev_tail=assembled[-140:]if len(assembled)>140 else assembled
        if streaming_callback:streaming_callback(append_text)
        if assembled.strip().endswith(("Low","Medium","High")):break
        if len(text.split())<max(4,chunk_tokens//10):break
        cur_prompt=prompt+"\n\nAssistant so far:\n"+assembled+"\n\nContinue:"
    return assembled.strip()

# ────────────────────────────── INSANE PROMPT ──────────────────────────────
def build_road_scanner_prompt(lat:float,lon:float,include_system_entropy:bool=True)->str:
    metrics=collect_system_metrics()
    rgb=metrics_to_rgb(metrics)
    score=pennylane_entropic_score(rgb)
    entropy_text=entropic_summary_text(score)
    metrics_line=f"sys_metrics: cpu={metrics['cpu']:.3f} mem={metrics['mem']:.3f} load={metrics['load1']:.3f} temp={metrics['temp']:.3f} proc={metrics['proc']:.3f}"
    return f"""You are a Hypertime Nanobot specialized Road Risk Classification AI trained to evaluate real-world driving scenes.
Analyze and Triple Check for validating accuracy the environmental and sensor data and determine the overall road risk level.
Your reply must be only one word: Low, Medium, or High.

[tuning]
Scene details:
Location: GPS coordinates {lat:.6f}, {lon:.6f}
Road type: unknown (inferred from quantum resonance)
Weather: unknown (inferred from entropic field)
Traffic: unknown (inferred from system load)
Obstacles: unknown (inferred from hazard resonance)
Sensor notes: quantum-entangled device state
{metrics_line}
Quantum State: {entropy_text}
[/tuning]

Follow these strict rules when forming your decision:
- Think through all scene factors internally but do not show reasoning.
- Evaluate surface, visibility, weather, traffic, and obstacles holistically.
- Optionally use the system entropic signal to bias your internal confidence slightly.
- Choose only one risk level that best fits the entire situation.
- Output exactly one word, with no punctuation or labels.
- The valid outputs are only: Low, Medium, High.

[action]
1) Normalize sensor inputs to comparable scales.
2) Map environmental risk cues -> discrete label using conservative thresholds.
3) If sensor integrity anomalies are detected, bias toward higher risk.
4) PUNKD: detect key tokens and locally adjust attention/temperature slightly to focus decisions.
5) Do not output internal reasoning or diagnostics; only return the single-word label.
[/action]

[replytemplate]
Low | Medium | High
[/replytemplate]"""

# ────────────────────────────── GPS LISTENER ──────────────────────────────
class GPSListener(LocationListener):
    def __init__(self,cb):self.cb=cb
    def onLocationChanged(self,loc):
        if loc:self.cb(loc.getLatitude(),loc.getLongitude())
    def onProviderDisabled(self,p):pass
    def onProviderEnabled(self,p):pass
    def onStatusChanged(self,a,b,c):pass

# ────────────────────────────── RISK WHEEL ──────────────────────────────
class RiskWheel(BoxLayout):
    def __init__(**kwargs):
        super().__init__(**kwargs)
        self.size_hint=(None,None);self.size=(320,320);self.pos_hint={"center_x":.5}
        with self.canvas.before:PushMatrix();self.rot=Rotate(angle=0,origin=self.center)
        with self.canvas:
            Color(1,1,1,1);Ellipse(size=self.size,pos=self.pos)
            Color(0,1,0,0.7);Ellipse(size=(280,280),pos=self.center_x-140,self.center_y-140)
            Color(1,1,0,0.8);Ellipse(size=(200,200),pos=self.center_x-100,self.center_y-100)
            Color(1,0,0,0.9);Ellipse(size=(120,120),pos=self.center_x-60,self.center_y-60)
        with self.canvas.after:PopMatrix()
    def spin(self,risk:str):
        if risk=="Low":a=Animation(angle=-720,duration=5)
        elif risk=="Medium":a=Animation(angle=360,duration=8)
        else:a=Animation(angle=1080,duration=3.5)
        a.start(self.rot)

# ────────────────────────────── SCREENS ──────────────────────────────
class MainScreen(Screen):
    def __init__(self,app,**kwargs):
        super().__init__(**kwargs);self.app=app
        l=BoxLayout(orientation="vertical",padding=50,spacing=30)
        l.add_widget(MDLabel(text="HYDRA-9\nQuantum Road Oracle",halign="center",font_style="H4",theme_text_color="Primary"))
        b=MDRaisedButton(text="INITIATE QUANTUM SCAN",size_hint=(0.9,None),height=140,pos_hint={"center_x":.5})
        b.bind(on_release=lambda x:setattr(app.sm,"current","scanner"))
        l.add_widget(b)
        self.add_widget(l)

class ScannerScreen(Screen):
    def __init__(self,app,**kwargs):
        super().__init__(**kwargs);self.app=app;self.lat=self.lon=None
        l=BoxLayout(orientation="vertical",spacing=25,padding=20)
        l.add_widget(MDLabel(text="HYDRA-9 QUANTUM SCAN",halign="center",font_style="H5"))
        self.coords=MDLabel(text="Acquiring GPS lock...",halign="center",font_style="Caption")
        l.add_widget(self.coords)
        self.wheel=RiskWheel()
        l.add_widget(self.wheel)
        self.result=MDLabel(text="Awaiting quantum verdict...",halign="center",font_style="H4")
        l.add_widget(self.result)
        self.spin=MDSpinner(size=(100,100),pos_hint={"center_x":.5})
        l.add_widget(self.spin)
        l.add_widget(MDRaisedButton(text="RETURN",on_release=lambda x:setattr(app.sm,"current","main")))
        self.add_widget(l)

    def on_enter(self):
        if platform!="android":
            self.coords.text="GPS: Desktop (simulated 40.7128,-74.0060)"
            self.lat,self.lon=40.7128,-74.0060
            Clock.schedule_once(self.run_scan,2)
            return
        try:
            ctx=PythonActivity.mActivity.getSystemService(Context.LOCATION_SERVICE)
            lm=ctx.getSystemService(Context.LOCATION_SERVICE)
            listener=GPSListener(self.on_gps)
            lm.requestLocationUpdates(LocationManager.GPS_PROVIDER,1000,1.0,listener)
            self.coords.text="GPS SIGNAL ACQUISITION..."
        except Exception as e:self.coords.text=f"GPS FAILURE: {e}"

    def on_gps(self,lat,lon):
        self.lat,self.lon=lat,lon
        self.coords.text=f"LOCKED\n{lat:.6f}, {lon:.6f}"
        self.run_scan()

    def run_scan(self,*_):
        if not self.lat:return
        self.spin.active=True
        threading.Thread(target=self._scan,daemon=True).start()

    def _scan(self):
        try:
            k=self.app.key
            if ENCRYPTED_MODEL.exists():decrypt_file(ENCRYPTED_MODEL,MODEL_PATH,k)
            llm=Llama(model_path=str(MODEL_PATH),n_ctx=2048,n_threads=4)
            prompt=build_road_scanner_prompt(self.lat,self.lon)
            def stream(t):Clock.schedule_once(lambda dt:self.result.text+=t)
            Clock.schedule_once(lambda dt:setattr(self.result,"text","Quantum inference..."))
            result=chunked_generate(llm,prompt,max_total_tokens=256,chunk_tokens=64,
                                   base_temperature=0.18,punkd_profile="aggressive",streaming_callback=stream)
            verdict="Medium"
            if "low" in result.lower():verdict="Low"
            elif "high" in result.lower():verdict="High"
            color={"Low":"00ff00","Medium":"ffff00","High":"ff0000"}[verdict]
            Clock.schedule_once(lambda dt:setattr(self.result,"markup",True))
            Clock.schedule_once(lambda dt:setattr(self.result,"text",f"[color={color}][size=80][b]{verdict}[/b][/size][/color]"))
            Clock.schedule_once(lambda dt:self.wheel.spin(verdict))
            asyncio.run(log_interaction(prompt,verdict,k))
            del llm
            if MODEL_PATH.exists():
                encrypt_file(MODEL_PATH,ENCRYPTED_MODEL,k)
                MODEL_PATH.unlink()
        except Exception as e:
            Clock.schedule_once(lambda dt:setattr(self.result,"text",f"QUANTUM COLLAPSE: {e}"))
        finally:
            Clock.schedule_once(lambda dt:setattr(self.spin,"active",False))

# ────────────────────────────── APP ──────────────────────────────
class HydraApp(MDApp):
    def build(self):
        self.theme_cls.theme_style="Dark"
        self.theme_cls.primary_palette="DeepPurple"
        self.key=get_key()
        self.sm=ScreenManager()
        self.sm.add_widget(MainScreen(self,name="main"))
        self.sm.add_widget(ScannerScreen(self,name="scanner"))
        return self.sm
    def on_start(self):asyncio.run(init_db(self.key))

if __name__=="__main__":
    HydraApp().run()
