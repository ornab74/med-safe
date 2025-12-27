[app]
# ----------------------------
# MedSafe — Buildozer config (WORKING for AlarmManager + inline Java generation)
# ----------------------------

title = MedSafe

# Keep package stable (changing breaks upgrades)
package.name = medsafellm
package.domain = com.medsafe

source.dir = .
source.main = main.py

# Human version + monotonically increasing version_code
# (bumped)
version = 0.1.23
android.version_code = 203746225

# ----------------------------
# Python / deps
# ----------------------------
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
# IMPORTANT:
# Build failed because android_src/extra_manifest.xml didn't exist.
# This spec assumes you either:
#   (A) COMMIT android_src/ into your repo (recommended), OR
#   (B) run: python main.py --gen-android  BEFORE buildozer runs (CI step).
include_patterns =
    *.py,
    *.kv,
    assets/*,
    *.json,
    android_src/*

# ----------------------------
# Android permissions
# ----------------------------
# - INTERNET for downloads
# - POST_NOTIFICATIONS for Android 13+
# - FOREGROUND_SERVICE only if you truly use a foreground service
# - SCHEDULE_EXACT_ALARM for exact alarms
# - RECEIVE_BOOT_COMPLETED to resync after reboot
# - WAKE_LOCK/VIBRATE optional
android.permissions = INTERNET,POST_NOTIFICATIONS,FOREGROUND_SERVICE,SCHEDULE_EXACT_ALARM,RECEIVE_BOOT_COMPLETED,WAKE_LOCK,VIBRATE

# ----------------------------
# Android Java sources + manifest injection (AlarmReceiver/BootReceiver)
# ----------------------------
# MUST exist at build time:
#   android_src/extra_manifest.xml
#   android_src/com/medsafe/medsafellm/AlarmReceiver.java
#   android_src/com/medsafe/medsafellm/BootReceiver.java
android.add_src = android_src
android.extra_manifest_xml = ./android_src/extra_manifest.xml

# ----------------------------
# Android services (optional)
# ----------------------------
# If you switch to AlarmManager-only reminders, remove this line AND remove FOREGROUND_SERVICE permission.
services = medservice:service/med_service.py:foreground:sticky

# ----------------------------
# SDK / NDK
# ----------------------------
android.sdk_path = /usr/local/lib/android/sdk

# If API 35 causes toolchain pain in CI, drop to 34 first.
android.api = 35
android.minapi = 23
android.ndk_api = 23
android.build_tools_version = 35.0.0

android.archs = arm64-v8a
p4a.bootstrap = sdl2

# Useful logs (optional)
android.logcat_filters = Python:V,ActivityManager:I,WindowManager:I

# Security
android.allow_backup = False


[buildozer]
log_level = 2
warn_on_root = 1
build_dir = .buildozer
android.accept_sdk_license = True
