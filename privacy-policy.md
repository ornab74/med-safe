# Privacy Policy – QRS Android

**Effective date:** December 13, 2025

This Privacy Policy describes how **QRS Android** (the “App”) handles information when you use it.

## 1) Developer

**Developer:** Graylan Janulis
**Contact:** [janulisgraylan@gmail.com](mailto:janulisgraylan@gmail.com)
**Country:** United States (USA)

---

## 2) Summary of what the App does

QRS Android provides two main features:

1. **Chat** with an on-device LLM using `llama_cpp` and a local GGUF model.
2. **Road Risk Scanner** that generates a “Low / Medium / High” risk label based on user-entered scene details and locally collected system signals.

The App is designed to keep data **on your device** by default.

---

## 3) Data the App processes

### A) User-provided data (stored locally)

The App processes and may store on your device:

* Messages you type into **Chat** (prompts)
* Model outputs returned to you (responses)
* Road Scanner inputs you type (location text you enter like “I-95 NB mile 12”, weather, obstacles, notes)
* Road Scanner result label (“Low/Medium/High”)

**Local storage behavior (encryption):**

* Chat and Road Scanner logs are stored in an **encrypted local database** (`chat_history.db.aes`) using AES-GCM encryption.
* The LLM model file can be stored **encrypted** on device (`.gguf.aes`). When you run the model, it may be temporarily **decrypted on-device**, then re-encrypted and the plaintext removed afterward.

### B) Device/system data (used locally)

To compute a “system entropy” signal and show stability/health info, the App may read:

* CPU usage, memory usage, load average, process count
* Thermal sensor readings (device temperature) if available via standard Linux/Android system paths

This system data is used to generate an internal score and is **not intended to identify you**.

### C) Network data (only when downloading the model)

The App can download the GGUF model from a remote host (currently a Hugging Face URL). When you use the download function:

* Your device will connect to that server
* The server will receive typical network metadata (e.g., IP address, user-agent, request timestamps) as part of normal web traffic

The App also computes a **SHA-256 hash** to help verify download integrity.

---

## 4) What the App does **not** collect

QRS Android does **not**:

* Create user accounts or require login
* Collect advertising ID
* Run ads or sell personal data
* Include built-in analytics/telemetry SDKs (unless you add them later)
* Collect precise GPS location (your “location” field in Road Scanner is user-entered text, not GPS)

---

## 5) How the App uses data

The App uses data to:

* Run local inference (chat and road risk classification)
* Save your chat history and scan history **encrypted** on-device
* Download and verify the model file when you request it
* Export a scan result to a JSON file if you choose

---

## 6) Sharing and third parties

We do **not sell** your data.

Data may be shared only in these limited cases:

* **Model download host:** If you download the model, your device connects to the hosting provider (e.g., Hugging Face) to fetch the file.
* **Legal requirements:** If required by law (for example, a valid court order).
* **Security:** To investigate abuse or protect the App and users, if necessary.

Other than model downloading, the App is designed to operate **without sending your prompts/responses off-device**.

---

## 7) Permissions (Android)

The App may request:

* **INTERNET**: used to download the model file when you choose that option.
* **READ/WRITE storage**: used to save/load model files and exported outputs (like JSON) that you choose to create.

You can revoke permissions in Android settings, but some features may stop working (for example, downloading or saving files).

---

## 8) Data retention and deletion

* Your chat/scan history remains on your device until you delete it (e.g., clearing app data or uninstalling).
* Exported JSON files remain wherever you saved them.
* You can remove downloaded models by deleting the model files or uninstalling the App.

---

## 9) Security

The App uses encryption (AES-GCM) for stored chat history and (optionally) for the model file. However, no software system is perfectly secure. You are responsible for keeping your device secure (screen lock, OS updates, etc.).

---

## 10) Children’s privacy

The App is not directed to children under 13, and we do not knowingly collect personal information from children.

---

## 11) Changes to this policy

If we change how QRS Android handles data (for example, adding cloud sync, analytics, or online inference), we will update this Privacy Policy and the effective date.

---

## 12) Contact

For privacy questions, contact: **[janulisgraylan@gmail.com](mailto:janulisgraylan@gmail.com)** (Graylan Janulis)


