# QRS Android

QRS Android is an AI powered Android app that runs an **on-device LLM** using **llama.cpp (`llama_cpp`)** to simulate Road Risk Hazards for researchers and users to test risk models. Users may input weather, traffic and locations to generate probablistic reports to improve road safety.

## Features
- **Chat** with a local GGUF model (offline inference)
- **Road Risk Scanner** that outputs **Low / Medium / High**
- **Encrypted local history** (chat + scans) stored on-device
- **Optional encrypted model at rest** (`.gguf.aes`) with temporary decrypt → use → re-encrypt flow

## Privacy Policy
See:
https://github.com/ornab74/qrs-android/blob/main/privacy-policy.md

## License
MIT — see `LICENSE`.
