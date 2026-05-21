
[app]

title = LightCap

package.name = lightcal
package.domain = com.qroadscan

source.dir = .
source.main = main.py

version = 0.1.5

android.version_code = 1024005

requirements = python3,kivy==2.2.1,kivymd,httpx,cryptography,aiosqlite,litert-lm


orientation = portrait
fullscreen = 0

include_patterns = models/*,*.gguf,*.aes,*.db,*.json

android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,CAMERA,RECORD_AUDIO,FOREGROUND_SERVICE,WAKE_LOCK

android.sdk_path = /usr/local/lib/android/sdk

android.api = 35
android.minapi = 26
android.ndk_api = 26

# NDK VERSION
android.ndk = 27c
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
