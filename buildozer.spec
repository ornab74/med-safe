[app]
# ----------------------------
# MedSafe — Buildozer config (updated for AlarmManager + version bump)
# ----------------------------

title = MedSafe

# Keep package stable (changing breaks upgrades)
package.name = medsafellm
package.domain = com.medsafe

source.dir = .
source.main = main.py

# Human version + monotonically increasing version_code
version = 0.1.22
android.version_code = 203746224

# ----------------------------
# Python / deps
# ----------------------------
# NOTE:


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
# Include android_src if you're adding Java receivers + manifest injection.
include_patterns =
    *.py,
    *.kv,
    assets/*,
    *.json,
    android_src/*

# ----------------------------
# Android permissions
# ----------------------------
# Existing:
# - INTERNET for downloads
# - FOREGROUND_SERVICE if you actually run a foreground sticky service
# - POST_NOTIFICATIONS for Android 13+
#
# AlarmManager persistence:
# - SCHEDULE_EXACT_ALARM for exact alarms
# - RECEIVE_BOOT_COMPLETED to resync after reboot
# - WAKE_LOCK/VIBRATE nice-to-have for reliable UX
#
# (Android 15 is API 35) 1
android.permissions = INTERNET, POST_NOTIFICATIONS, FOREGROUND_SERVICE, SCHEDULE_EXACT_ALARM, RECEIVE_BOOT_COMPLETED, WAKE_LOCK, VIBRATE

# ----------------------------
# Android Java sources + manifest injection (for AlarmReceiver/BootReceiver)
# ----------------------------
# Your main.py --gen-android should create:
#   android_src/<com>/<medsafe>/<...>.java
#   android_src/extra_manifest.xml
#
# Buildozer supports adding src + extra manifest injection. 
android.add_src = android_src
android.extra_manifest_xml = android_src/extra_manifest.xml

# ----------------------------
# Android services (background reminders)
# ----------------------------
# If you SWITCH to AlarmManager-only reminders, you can remove the service line
# and drop FOREGROUND_SERVICE permission.
services = medservice:service/med_service.py:foreground:sticky

# ----------------------------
# SDK / NDK
# ----------------------------
android.sdk_path = /usr/local/lib/android/sdk

# API 35 == Android 15 3
# NOTE: Some people hit build issues when pushing very new APIs/toolchains; if you hit that,
# drop android.api to 34 while keeping minapi. 4
android.api = 35
android.minapi = 23
android.ndk_api = 23

android.build_tools_version = 35.0.0

# Target arch
android.archs = arm64-v8a

p4a.bootstrap = sdl2


# Security
android.allow_backup = False


[buildozer]
log_level = 2
warn_on_root = 1
build_dir = .buildozer
android.accept_sdk_license = True
