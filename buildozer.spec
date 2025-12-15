
[app]

title = Secure LLM Road Scanner

package.name = securellmroads
package.domain = com.qroadscan

source.dir = .
source.main = main.py

version = 0.1.3

android.version_code = 1024003

requirements = python3,kivy==2.2.1,kivymd,httpx,cryptography,aiosqlite,psutil,pennylane,llama_cpp_python

p4a.local_recipes = ./p4a_recipes

orientation = portrait
fullscreen = 0

include_patterns = models/*,*.gguf,*.aes,*.db,*.json

android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

android.sdk_path = /usr/local/lib/android/sdk

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
