[app]

# APP INFO
title = QRS — Quantum Road Scanner
package.name = qrs
package.domain = com.chaosresonance
version = 7.7.7

# SOURCE FILES
source.dir = .
source.include_exts = py,png,jpg,jpeg,ttf,otf,kv,atlas,gguf,aes,db,txt,md
source.exclude_patterns = .git,.buildozer,bin,__pycache__,*.pyc,*.pyo,*.log,tmp.db

# REQUIREMENTS — 2025 GOLDEN COMBO (do not change)
requirements = python3==3.11.9,\
kivy==2.3.0,\
kivymd==1.2.0,\
numpy,\
pyjnius,\
android,\
psutil,\
httpx,\
aiosqlite,\
cryptography==42.0.8,\
pennylane==0.36.0,\
pennylane-lightning==0.36.0,\
llama-cpp-python==0.2.85

# These two MUST be pre-installed or GitHub Actions fails
android.pip_install_pre = cryptography==42.0.8,pennylane-lightning==0.36.0

# VISUAL
orientation = portrait
fullscreen = 0
presplash.filename = %(source.dir)s/data/presplash.png
icon.filename = %(source.dir)s/data/icon.png

# ANDROID TARGET
android.api = 34
android.minapi = 24
android.sdk = 34
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a

# PERMISSIONS — minimal and Google Play approved
android.permissions = INTERNET,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,FOREGROUND_SERVICE

# BUILDOZER / P4A SETTINGS
p4a.branch = develop
android.accept_sdk_license = True
android.private_storage = False
android.allow_backup = False
android.extra_args = --enable-preview

# LOGGING
log_level = 2
```ini
2
android.logcat_filters = *:S python:D

[buildozer]
log_level = 2
warn_on_root = 1
