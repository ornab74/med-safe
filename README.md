
# MedSafe — Offline Medication Reminders + Dose Safety (Low / Medium / High)

MedSafe is an Android-first Kivy/KivyMD app that:
- stores your medication schedules locally (encrypted),
- reminds you when meds are due (background foreground-service),
- checks a dose request using a **Low / Medium / High** safety label,
- optionally uses a **local llama.cpp model** (≈100MB) for a strict single-word risk label,
- falls back to a deterministic heuristic if the model is missing/unavailable.

No accounts. No cloud inference. Your data stays on-device.

---

## Features

### 1) Multi-med schedule + reminders
- Add multiple meds, each with:
  - **Dose (mg)**
  - **Interval (hours)** (e.g., every 8 hours)
  - **Max daily (mg)** (optional)
- App computes next due time and shows status (overdue / next in N minutes).
- A background service can post reminders while the UI app is closed.

### 2) Dose safety classification (Low / Medium / High)
When you press **Log Dose Now**:
- MedSafe evaluates whether that dose is:
  - **Low**: timing + daily totals look safe
  - **Medium**: close to interval or close to daily max
  - **High**: too soon or exceeds daily max (or strongly suggests risk)

MedSafe always displays the safety label with a dial UI.

### 3) Offline LLM (llama.cpp) integration (optional but supported)
- On first run, MedSafe can **download** a small GGUF model (~100MB).
- It verifies SHA-256.
- It encrypts the model and stores it on device.
- For classification, it decrypts to a temporary plaintext file for llama.cpp, then deletes it.

If the model is not present (or fails), MedSafe uses the **heuristic** safety classifier.

### 4) Local encrypted storage (vault)
Med schedules + dose history are stored in an encrypted JSON “vault”:
- AES-GCM encryption
- per-install key material stored in app-private storage

---

## Safety notes (read this)
MedSafe is a reminder + consistency tool, not medical advice.
- It cannot know your full medical situation, interactions, kidney/liver function, etc.
- Always follow your prescription label and clinician guidance.
- If you suspect an overdose or severe reaction, seek urgent help.

The LLM risk label is constrained to “Low/Medium/High” and is only meant to reflect the numerical schedule/dose facts you entered.

---

## Data model

Each medication entry looks like this:

```json
{
  "id": "a1b2c3d4e5f6",
  "name": "Ibuprofen",
  "dose_mg": 200,
  "interval_hours": 8,
  "max_daily_mg": 1200,
  "last_taken_ts": 0,
  "history": [
    [1734991200.0, 200],
    [1735020000.0, 200]
  ]
}
