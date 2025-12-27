[app]
title = MedSafe

package.name = medsafellm
package.domain = com.medsafe

source.dir = .
source.main = main.py

version = 0.1.24
android.version_code = 203746226

requirements = python3,kivy==2.2.1,kivymd,httpx,cryptography,aiosqlite,psutil,pennylane,llama_cpp_python

p4a.local_recipes = ./p4a_recipes

orientation = portrait
fullscreen = 0

include_patterns =
    *.py,
    *.kv,
    assets/*,
    *.json,
    service/*

# Permissions
android.permissions = INTERNET,POST_NOTIFICATIONS,FOREGROUND_SERVICE,WAKE_LOCK,VIBRATE

# Foreground sticky python service
services = medservice:service/med_service.py:foreground:sticky

android.sdk_path = /usr/local/lib/android/sdk
android.api = 35
android.minapi = 23
android.ndk_api = 23
android.build_tools_version = 35.0.0
android.archs = arm64-v8a
p4a.bootstrap = sdl2

android.allow_backup = False


[buildozer]
log_level = 2
warn_on_root = 1
build_dir = .buildozer
android.accept_sdk_license = True
