
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

# (str) Application versioning (method 1)
version = 0.1.0

# (list) Application requirements
# NOTE: llama-cpp-python / pennylane are heavy & may require custom recipes,
# but they are listed to match your Python code exactly.
requirements = python3,kivy==2.2.1,kivymd,httpx,cryptography,aiosqlite,psutil,pennylane,llama-cpp-python

# (str) Application orientation (one of landscape, portrait or all)
orientation = portrait

# (bool) Indicate if the application should be fullscreen or not
fullscreen = 0

# (list) Patterns to include in the APK (for models, encrypted db, etc.)
include_patterns = models/*,*.gguf,*.aes,*.db,*.json

# (list) Permissions
android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# (str) Supported Android architecture
android.archs = armeabi-v7a, arm64-v8a

# (int) Target Android API
android.api = 33

# (int) Minimum Android API
android.minapi = 21

# (str) Android SDK path (can be left empty and handled by buildozer)
#android.sdk_path =

# (str) Android NDK path (can be left empty and handled by buildozer)
#android.ndk_path =

# (str) Android NDK version
android.ndk = 23b

# (str) Bootstrap to use for Android
android.bootstrap = sdl2

# (str) Application icon
#icon.filename = %(source.dir)s/data/icon.png

# (str) Presplash image
#presplash.filename = %(source.dir)s/data/presplash.png

# (list) Android features (if any)
#android.features = android.hardware.camera,android.hardware.location

# (bool) Copy library instead of using a link (useful for some libs)
#android.copy_libs = 1

# (str) Application entrypoint arguments (if any)
#arguments =

# (str) Custom Java source files
#android.add_src =

# (list) Custom Java compile options
#android.add_compile_options =

# (list) Gradle dependencies to add
#android.gradle_dependencies =

# (list) Add custom maven repos
#android.maven_repositories =

# (str) Custom package name (Java)
#android.manifest.application.custom_name =

# (list) Logcat filters to use
android.logcat_filters = Python:V,ActivityManager:I,WindowManager:I

# (bool) Prevent backup of application data
android.allow_backup = False

# (bool) Keep virtual keyboard visible
#android.keyboard_mode = docked

# (str) Android entry point
#android.entrypoint = org.kivy.android.PythonActivity

# (str) OUYA category
#android.ouya.category = GAME

# (list) Android extra manifest XML files
#android.extra_manifests =

# (str) Custom manifest XML content
#android.manifest.extra =

# (str) Custom application manifest XML content
#android.manifest.application.extra =

# (str) Custom manifest intent filters
#android.manifest.intent_filters =

# (list) Android services to declare
#services =

# (str) Path to Python-for-Android git repo (if using local p4a)
#p4a.local_recipes = ./p4a-recipes

# (str) Branch to use for p4a
#p4a.branch = master

# (str) P4A bootstrap (alternate name)
#p4a.bootstrap = sdl2

# (int) P4A minimum API
#p4a.minapi = 21

# (bool) Use compiled python (cpython)
#python3 = True

# (str) Entry point to be used if you use pyproject / poetry etc.
#project_dir = .

# (str) Kivy version used on desktop (for testing)
#osx.kivy_version = 2.2.1
#osx.python_version = 3.11.0

# ======================================================================
# iOS section (leave default if you only target Android)
# ======================================================================

# (list) iOS requirements
#ios.kivy_version = 2.2.1
#ios.python_version = 3.11.0
#ios.include_patterns =

# ======================================================================
# Buildozer section
# ======================================================================

[buildozer]

# (int) Log level (0 = quiet, 1 = normal, 2 = verbose, 3 = debug)
log_level = 2

# (str) Buildozer output directory
#build_dir = ./.buildozer

# (int) Number of concurrent jobs (0 = auto)
#jobs = 0

# (bool) Use color in output
#color = 1

# (bool) Warn the user if running as root
warn_on_root = 1

# (str) Default command to run on `buildozer` without args
#default_command = android debug

# (bool) Allow to run buildozer inside Docker container
#docker = 0
