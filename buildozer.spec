[app]
title = QRS — Quantum Road Scanner
package.name = qrs
package.domain = com.chaosresonance
version = 7.7.7
android.numeric_version = 777

source.dir = .
source.include_exts = py,png,jpg,jpeg,ttf,otf,kv,atlas,gguf,aes,db,txt,md,json,wav
source.exclude_dirs = .git,.buildozer,bin,__pycache__,.github,.venv

requirements = python3==3.11.9, kivy==2.3.0, https://github.com/kivymd/KivyMD/archive/master.zip, numpy, pyjnius, android, psutil, httpx, aiosqlite, cryptography, pennylane==0.36.0,pennylane-lightning==0.36.0,llama-cpp-python==0.2.85
android.archs = arm64-v8a
p4a.branch = develop
p4a.fork = kivy

android.ndk_api = 35
android.minapi = 24
android.api = 35
android.sdk = 35
android.ndk = 27
android.release_artifact = aab

android.permissions = ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,FOREGROUND_SERVICE,FOREGROUND_SERVICE_DATA_SYNC
android.block_network_permissions = True

orientation = portrait
fullscreen = 0
presplash.filename = %(source.dir)s/data/presplash.png
icon.filename = %(source.dir)s/data/icon.png
android.add_compile_options = -DSDL_SENSOR_DISABLED=1

android.accept_sdk_license = True
android.private_storage = False
android.allow_backup = False

log_level = 2

[buildozer]
log_level = 2
warn_on_root = 1
