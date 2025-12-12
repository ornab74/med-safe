[app]

# (str) Title of your application
title = Secure LLM Road Scanner

# (str) Package name (no dots, all lowercase)
package.name = securellmroads

# (str) Package domain (reverse-DNS style, must be valid)
package.domain = com.qroadscan

# (str) Source code directory (where main.py lives)
source.dir = .

# (str) Main .py file
source.main = main.py

# (str) Application version
version = 0.1.0

# (str) Application version code (integer, optional)
# android.version_code = 1

# ---------------------------------------------------------
#  PYTHON / p4a REQUIREMENTS
# ---------------------------------------------------------
# We KEEP all the heavy libs.
# llama_cpp_python is a custom p4a recipe that builds
# the pip package llama-cpp-python for Android.
requirements = python3,kivy==2.2.1,kivymd,httpx,cryptography,aiosqlite,psutil,pennylane,llama_cpp_python

# Tell python-for-android where our custom recipes live
p4a.local_recipes = ./p4a_recipes

# Optionally pin a p4a branch if you want
# p4a.branch = master

# (str) Orientation (portrait, landscape or all)
orientation = portrait

# (bool) Fullscreen mode (0 or 1)
fullscreen = 0

# (list) Files/patterns to include in the APK
include_patterns = models/*,*.gguf,*.aes,*.db,*.json

# (list) Permissions
android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# ---------------------------------------------------------
#  ANDROID / SDK / BUILD-TOOLS
# ---------------------------------------------------------

# Android SDK path (we install it here in the workflow)
android.sdk_path = /usr/local/lib/android/sdk

# ❌ DO NOT set android.ndk_path on CI, it causes permission errors.
# Let Buildozer download & keep the NDK under .buildozer.
# android.ndk_path = /usr/local/lib/android/ndk

# (int) Android API to build against
android.api = 34

# (int) Minimum supported Android API
android.minapi = 21

# (str) Build-tools version
android.build_tools_version = 34.0.0

# (str) Architectures
android.archs = arm64-v8a

# (str) Bootstrap for Android
p4a.bootstrap = sdl2

# (list) Android features if needed
# android.features = android.hardware.camera,android.hardware.location

# Icon / presplash (optional)
# icon.filename = %(source.dir)s/data/icon.png
# presplash.filename = %(source.dir)s/data/presplash.png

# (list) Logcat filters
android.logcat_filters = Python:V,ActivityManager:I,WindowManager:I

# (bool) Disallow/allow backup
android.allow_backup = False


[buildozer]

# (int) Log level (0 quiet, 1 normal, 2 verbose, 3 debug)
log_level = 2

# (bool) Warn if running as root
warn_on_root = 1

# (str) Default command when running just `buildozer`
# default_command = android debug

# (str) Directory where to store compiled parts
build_dir = .buildozer

# Auto-accept SDK licenses (CI still runs sdkmanager --licenses)
android.accept_sdk_license = True
