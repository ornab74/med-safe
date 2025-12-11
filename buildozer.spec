[app]

# (str) Title of your application
title = Secure LLM Road Scanner

# (str) Package name
package.name = securellmroads

# (str) Package domain (must be a valid domain)
package.domain = com.qroadscan

# (str) Source code directory
source.dir = .

# (str) Main .py file
source.main = main.py

# (str) Application versioning
version = 0.1.0

# (list) Application requirements
requirements = python3,kivy==2.2.1,kivymd,httpx,cryptography,aiosqlite,psutil,pennylane,llama-cpp-python

# (str) Application orientation (one of landscape, portrait or all)
orientation = portrait

# (bool) Indicate if the application should be fullscreen or not
fullscreen = 0

# (list) Patterns to include in the APK (for models, encrypted db, etc.)
include_patterns = models/*,*.gguf,*.aes,*.db,*.json

# (list) Permissions
android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# ---------- ANDROID SDK / API / BUILD-TOOLS PINNING ----------

# (str) Path to the system Android SDK (set by GitHub Actions)
# This matches the SDK path on ubuntu-latest runners
android.sdk_path = /usr/local/lib/android/sdk

# (int) Target Android API
android.api = 34

# (int) Minimum Android API
android.minapi = 21

# (str) Specific build-tools version to use
android.build_tools_version = 34.0.0

# (str) Supported Android architectures
android.archs = armeabi-v7a, arm64-v8a

# (str) Bootstrap to use for Android
android.bootstrap = sdl2

# (str) Application icon (optional)
#icon.filename = %(source.dir)s/data/icon.png

# (str) Presplash image (optional)
#presplash.filename = %(source.dir)s/data/presplash.png

# (list) Android features (if any)
#android.features = android.hardware.camera,android.hardware.location

# (list) Logcat filters to use
android.logcat_filters = Python:V,ActivityManager:I,WindowManager:I

# (bool) Prevent backup of application data
android.allow_backup = False


[buildozer]

# (int) Log level (0 = quiet, 1 = normal, 2 = verbose, 3 = debug)
log_level = 2

# (bool) Warn the user if running as root
warn_on_root = 1

# (str) Default command to run on `buildozer` without args
#default_command = android debug
