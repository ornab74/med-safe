
[app]
# ----------------------------
# MedSafe — Buildozer config
# ----------------------------

title = MedSafe

# Keep package stable (changing breaks upgrades)
package.name = medsafellm
package.domain = com.medsafe

source.dir = .
source.main = main.py

# Human version + monotonically increasing version_code
version = 0.1.20
android.version_code = 203746222

# ----------------------------
# Python / deps
# ----------------------------
# Notes:
# - p4a typically expects pip name "llama-cpp-python" (not llama_cpp_python).
# - If you use a custom recipe for llama, keep p4a.local_recipes and still list the pip name.
# - httpx is optional if you're using urllib for download; keep if you prefer httpx.


requirements = python3,kivy==2.2.1,kivymd,httpx,cryptography,aiosqlite,psutil,pennylane,llama_cpp_python

p4a.local_recipes = ./p4a_recipes

# ----------------------------
# App behavior
# ----------------------------
orientation = portrait
fullscreen = 0

# ----------------------------
# Assets / includes
# ----------------------------
# MedSafe downloads model on first run, encrypts it locally.
# So you generally do NOT ship any model files.
include_patterns =
    *.py,
    *.kv,
    assets/*,
    *.json

# If you ship a default DB/schema, add:
# include_patterns = ..., *.db

# ----------------------------
# Android permissions
# ----------------------------
# If you auto-download a model: INTERNET
# If you run a foreground sticky service for reminders: FOREGROUND_SERVICE
# Android 13+ notifications: POST_NOTIFICATIONS
android.permissions =
    INTERNET,
    FOREGROUND_SERVICE,
    POST_NOTIFICATIONS

# If you implement exact alarms (optional): SCHEDULE_EXACT_ALARM
# android.permissions = INTERNET,FOREGROUND_SERVICE,POST_NOTIFICATIONS,SCHEDULE_EXACT_ALARM

# ----------------------------
# Android services (background reminders)
# ----------------------------
# If you add a background service file:
#   service/med_service.py
# Use foreground:sticky so the OS keeps it more reliably.
services = medservice:service/med_service.py:foreground:sticky

# ----------------------------
# SDK / NDK
# ----------------------------
android.sdk_path = /usr/local/lib/android/sdk

android.api = 35
android.minapi = 23
android.ndk_api = 23

android.build_tools_version = 35.0.0

# Target arch
android.archs = arm64-v8a

p4a.bootstrap = sdl2

# Useful logs
android.logcat_filters = Python:V,ActivityManager:I,WindowManager:I

# Security
android.allow_backup = False


[buildozer]
log_level = 2
warn_on_root = 1
build_dir = .buildozer
android.accept_sdk_license = True



