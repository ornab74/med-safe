[app]
title = MedSafe

package.name = medsafellm
package.domain = com.medsafe

source.dir = .
source.main = main.py

version = 0.1.23
android.version_code = 203746225

requirements = python3,kivy==2.2.1,kivymd,httpx,cryptography,aiosqlite,psutil,pennylane,llama_cpp_python
p4a.local_recipes = ./p4a_recipes

orientation = portrait
fullscreen = 0

include_patterns =
    *.py,
    *.kv,
    assets/*,
    *.json,
    android_src/*

# Permissions for alarms + boot + notifications
android.permissions = INTERNET,POST_NOTIFICATIONS,SCHEDULE_EXACT_ALARM,RECEIVE_BOOT_COMPLETED,WAKE_LOCK,VIBRATE,FOREGROUND_SERVICE

# Compile your Java receivers (AlarmReceiver.java / BootReceiver.java) from android_src/
android.add_src = android_src

# ✅ Inline manifest injection (NO FILE NEEDED)
# This injects inside <application>...</application>
android.extra_manifest_application_arguments =
    <receiver android:name="com.medsafe.medsafellm.AlarmReceiver" android:exported="false" />
    <receiver android:name="com.medsafe.medsafellm.BootReceiver" android:exported="false">
        <intent-filter>
            <action android:name="android.intent.action.BOOT_COMPLETED" />
            <action android:name="android.intent.action.LOCKED_BOOT_COMPLETED" />
        </intent-filter>
    </receiver>

# If you really use this service, keep it. If not, remove it + FOREGROUND_SERVICE perm.
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
