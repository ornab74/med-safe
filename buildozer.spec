[app]
# ----------------------------
# MedSafe — Buildozer config (WORKING: AlarmManager receivers + no extra_manifest.xml file)
# ----------------------------

title = MedSafe

# Keep package stable (changing breaks upgrades)
package.name = medsafellm
package.domain = com.medsafe

source.dir = .
source.main = main.py

# Human version + monotonically increasing version_code
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
# - SCHEDULE_EXACT_ALARM for exact alarms
# - RECEIVE_BOOT_COMPLETED to resync after reboot
# - WAKE_LOCK/VIBRATE optional, improves reliability/UX
# - FOREGROUND_SERVICE only needed if you truly run a foreground service
android.permissions = INTERNET,POST_NOTIFICATIONS,SCHEDULE_EXACT_ALARM,RECEIVE_BOOT_COMPLETED,WAKE_LOCK,VIBRATE,FOREGROUND_SERVICE

# ----------------------------
# Android Java sources + manifest injection (NO extra_manifest.xml file required)
# ----------------------------
# You must have these files committed in your repo:
#   android_src/com/medsafe/medsafellm/AlarmReceiver.java
#   android_src/com/medsafe/medsafellm/BootReceiver.java
android.add_src = android_src

# IMPORTANT:
# Must be a SINGLE LINE, otherwise buildozer may misinterpret it as a filename and try to open() it.
android.extra_manifest_application_arguments = '<receiver android:name="com.medsafe.medsafellm.AlarmReceiver" android:exported="false" /><receiver android:name="com.medsafe.medsafellm.BootReceiver" android:exported="false"><intent-filter><action android:name="android.intent.action.BOOT_COMPLETED" /><action android:name="android.intent.action.LOCKED_BOOT_COMPLETED" /></intent-filter></receiver>'
# Android services (optional)
# ----------------------------
# If you switch to AlarmManager-only reminders, remove this line AND remove FOREGROUND_SERVICE permission.
services = medservice:service/med_service.py:foreground:sticky

# ----------------------------
# SDK / NDK
# ----------------------------
android.sdk_path = /usr/local/lib/android/sdk

# If API 35 causes toolchain problems in CI, set android.api = 34
android.api = 35
android.minapi = 23
android.ndk_api = 23
android.build_tools_version = 35.0.0

# Target arch
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
```0
