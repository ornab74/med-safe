
[app]
title = Road Safe

package.name = securellmroads
package.domain = com.qroadscan

source.dir = .
source.main = main.py

version = 0.1.12
android.version_code = 1025012

# No network/db deps now. Keep only what you actually import.
requirements = python3,kivy==2.2.1,kivymd,cryptography,llama_cpp_python

# If you truly use jnius on Android, add it:
# requirements = python3,kivy==2.2.1,kivymd,cryptography,llama_cpp_python,pyjnius

p4a.local_recipes = ./p4a_recipes

orientation = portrait
fullscreen = 0

# Ship everything needed for offline model+bootstrap.
# - models/*.aes              (encrypted gguf)
# - models/*.mdk.wrap         (bootstrap-wrapped MDK)
# - models/*.sha256           (plaintext gguf hash to verify after decrypt)
# - bootstrap_secret.py       (build-time injected secret module)
# - any kv/json assets you use
include_patterns = \
    main.py, \
    bootstrap_secret.py, \
    models/*.aes, \
    models/*.mdk.wrap, \
    models/*.sha256, \
    models/*.json, \
    *.kv, \
    assets/*

# No permissions (offline).
android.permissions =

# Build config
android.api = 35
android.minapi = 23
android.ndk_api = 23
android.build_tools_version = 35.0.0
android.archs = arm64-v8a

p4a.bootstrap = sdl2

android.logcat_filters = Python:V,ActivityManager:I,WindowManager:I

android.allow_backup = False


[buildozer]
log_level = 2
warn_on_root = 1
build_dir = .buildozer
android.accept_sdk_license = True
