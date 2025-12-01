[app]
title = QRS — Quantum Road Scanner
package.name = qrs
package.domain = com.chaosresonance
version = 7.7.7
android.numeric_version = 777

source.dir = .
source.include_exts = py,png,jpg,jpeg,ttf,otf,kv,atlas,gguf,aes,db,txt,md,json,wav
source.exclude_dirs = .git,.buildozer,bin,__pycache__,.github,.venv
source.exclude_patterns = *.pyc,*.pyo,*.log,tmp.db,*.bak

requirements = python3==3.11.9,kivy==2.3.0,kivymd==1.2.0,numpy,pyjnius,android,psutil,httpx,aiosqlite,cryptography==42.0.8,pennylane==0.36.0,pennylane-lightning==0.36.0,llama-cpp-python==0.2.85
android.pip_install_pre = cryptography==42.0.8,pennylane-lightning==0.36.0

orientation = portrait
fullscreen = 0
presplash.filename = %(source.dir)s/data/presplash.png
icon.filename = %(source.dir)s/data/icon.png

android.api = 35
android.minapi = 24
android.sdk = 35
android.ndk = 28c
android.release_artifact = aab
android.archs = arm64-v8a, armeabi-v7a

android.permissions = INTERNET,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,FOREGROUND_SERVICE,FOREGROUND_SERVICE_DATA_SYNC

p4a.branch = develop
p4a.patch_ignore_errors = True
p4a.setup_py_ignore_patch_errors = True
# Fixed: Ignore failed patches (e.g., 3.14_armv7l_fix for Python 3.11.9)
p4a.extra_args = --ignore-patch-errors
android.accept_sdk_license = True
android.private_storage = False
android.allow_backup = False
android.extra_args = --enable-preview --ignore-setup-py-errors

log_level = 2
android.logcat_filters = *:S python:D

[buildozer]
log_level = 2
warn_on_root = 1
