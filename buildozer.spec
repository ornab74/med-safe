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

# (str) Application version code (integer, optional but recommended)
# android.version_code = 1

# -------------------------------------------------------------
# Python / p4a configuration
# -------------------------------------------------------------

# (list) Application requirements (python-for-android recipes)
# llama_cpp_python == your custom recipe that builds llama-cpp-python
requirements = python3,kivy==2.2.1,kivymd,httpx,cryptography,aiosqlite,psutil,pennylane,llama_cpp_python

# (str) Path to your custom p4a recipes
p4a.local_recipes = ./p4a_recipes

# (str) Orientation (portrait, landscape or all)
orientation = portrait

# (bool) Fullscreen mode (0 or 1)
fullscreen = 0

# (list) Files/patterns to include in the APK
include_patterns = models/*,*.gguf,*.aes,*.db,*.json

# (list) Permissions
android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# -------------------------------------------------------------
# ANDROID / SDK / BUILD-TOOLS
# -------------------------------------------------------------

# (str) Path to Android SDK (CI installs here)
android.sdk_path = /usr/local/lib/android/sdk

# (str) Path to Android NDK (optional; p4a can download if missing)
# android.ndk_path = /usr/local/lib/android/ndk

# (int) Android API to build against
android.api = 34

# (int) Minimum supported Android API
android.minapi = 21

# (str) Build-tools version
android.build_tools_version = 34.0.0

# (str) Architectures
android.archs = armeabi-v7a, arm64-v8a

# (str) Bootstrap for Android
# android.bootstrap is deprecated → use p4a.bootstrap
p4a.bootstrap = sdl2

# (str) Icon / presplash (optional)
# icon.filename = %(source.dir)s/data/icon.png
# presplash.filename = %(source.dir)s/data/presplash.png

# (list) Android features if needed
# android.features = android.hardware.camera,android.hardware.location

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

# (bool) Automatically accept SDK licenses
# (CI still calls `yes | sdkmanager --licenses`)
# android.accept_sdk_license = True
