[app]
title = QRS — Quantum Road Scanner
package.name = qrs
package.domain = com.chaosresonance
version = 7.7.7
android.numeric_version = 777

source.dir = .
source.include_exts = py,png,jpg,jpeg,ttf,otf,kv,atlas,gguf,aes,db,txt,md,json,wav,so
source.exclude_dirs = .git,.buildozer,bin,__pycache__,.github,.venv
source.exclude_patterns = *.pyc,*.pyo,*.log,tmp.db,*.bak

requirements = python3==3.11.9,https://github.com/kivymd/KivyMD/archive/master.zip,kivy==2.3.0,numpy,pyjnius,android,psutil,httpx,aiosqlite,cryptography,pennylane==0.36.0,pennylane-lightning==0.36.0,llama-cpp-python==0.2.85

orientation = portrait
fullscreen = 0
presplash.filename = %(source.dir)s/data/presplash.png
icon.filename = %(source.dir)s/data/icon.png

p4a.branch = develop
p4a.fork = kivy

android.api = 35
android.minapi = 24
android.sdk = 35
android.ndk = 26
android.release_artifact = aab
android.archs = arm64-v8a, armeabi-v7a

android.permissions = INTERNET,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,FOREGROUND_SERVICE,FOREGROUND_SERVICE_DATA_SYNC

android.accept_sdk_license = True
log_level = 2

[buildozer]
log_level = 2
warn_on_root = 1
