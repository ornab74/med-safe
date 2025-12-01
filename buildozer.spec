[app]
title = QRS — Quantum Road Scanner
package.name = qrs
package.domain = com.chaosresonance
version = 7.7.7
android.numeric_version = 777

source.dir = .
source.include_exts = py,png,jpg,jpeg,ttf,otf,kv,atlas,gguf,aes,db,txt,md,json,wav
source.exclude_dirs = .git,.buildozer,bin,__pycache__,.github,.venv

requirements = python3==3.11.9,kivy,kivymd,numpy,pyjnius,android,psutil,httpx,aiosqlite,cryptography==42.0.8,pennylane==0.36.0,pennylane-lightning==0.36.0,llama-cpp-python
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

p4a.branch = master
android.accept_sdk_license = True
android.private_storage = False
android.allow_backup = False

p4a.patches = patches/sdl2_pollonce.patch

log_level = 2

[buildozer]
log_level = 2
warn_on_root = 1
