# Bionic FakeLock Patcher

[English](README.md) | [Tiếng Việt](README_VI.md)

Universal FakeLock and Bootloader Spoofing solution for Android ARM64 & ARM32 (AArch64) & ARM32 (ARMv7-a Thumb-2).  
Provides both **C/C++ Source Patches** (for AOSP/ROM builders) and **Binary ASM Reverse Engineering Hooks** (for Stock OEM ROMs without source code).

Intercepts native and framework property lookups to spoof locked bootloader states without Magisk, KernelSU, or userspace hooking frameworks.

---

## Two Approaches: Source vs Binary Patching

Depending on whether you have source code or are modifying a closed-source stock OEM ROM, this repository provides two complementary paths:

```
                          ┌───────────────────────────┐
                          │   Android Bootloader      │
                          │   Unlocked (ro.boot.*)    │
                          └─────────────┬─────────────┘
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼                                                     ▼
   [Approach A: Source Tree]                            [Approach B: Stock ROM]
   Custom ROM / AOSP compilation                        No source code / Stripped ELF
   Apply C/C++ Git Patches                              Binary Patching via ASM Hooks
   ├── bionic (libc)                                    ├── patcher.py (Automated)
   └── frameworks/base (JNI)                            └── Code Cave ARM64 Injection
             │                                                     │
             └──────────────────────────┬──────────────────────────┘
                                        ▼
                          ┌───────────────────────────┐
                          │ ro.boot.flash.locked = 1  │
                          │ verifiedbootstate = green │
                          │ vbmeta.device_state=locked│
                          │  100% Zero-Root Bypass    │
                          └───────────────────────────┘
```

---

## Approach A: C/C++ Source Patches (For ROM Builders)

If you are compiling AOSP, LineageOS, or a custom ROM from source, apply the git patches located in [`patches/`](patches/):

### 1. Bionic C Library Patch
File: [`patches/0001-bionic-fake-bootloader-locked.patch`](patches/0001-bionic-fake-bootloader-locked.patch)  
Target: `bionic/libc/system_properties/system_properties.cpp`  

```cpp
--- a/libc/system_properties/system_properties.cpp
+++ b/libc/system_properties/system_properties.cpp
@@ -322,6 +322,10 @@ void SystemProperties::ReadCallback(const prop_info* pi,
   if (is_read_only(pi->name)) {
     uint32_t serial = load_const_atomic(&pi->serial, memory_order_relaxed);
+    if (strcmp(pi->name, "ro.boot.flash.locked") == 0)
+     callback(cookie, pi->name, "1", serial);
+    if (strcmp(pi->name, "ro.boot.verifiedbootstate") == 0)
+     callback(cookie, pi->name, "green", serial);
     if (pi->is_long()) {
       callback(cookie, pi->name, pi->long_value(), serial);
```

### 2. Framework JNI Patch
File: [`patches/0002-frameworks-base-fake-bootloader-locked.patch`](patches/0002-frameworks-base-fake-bootloader-locked.patch)  
Target: `frameworks/base/core/jni/android_os_SystemProperties.cpp`  

```cpp
--- a/core/jni/android_os_SystemProperties.cpp
+++ b/core/jni/android_os_SystemProperties.cpp
@@ -81,6 +81,18 @@ jstring SystemProperties_getSS(JNIEnv* env, jclass clazz, jstring keyJ,
                                jstring defJ)
 {
+    const char* key = env->GetStringUTFChars(keyJ, nullptr);
+    if (strcmp(key, "ro.boot.flash.locked") == 0) {
+        env->ReleaseStringUTFChars(keyJ, key);
+        return env->NewStringUTF("1");
+    }
+    if (strcmp(key, "ro.boot.verifiedbootstate") == 0) {
+        env->ReleaseStringUTFChars(keyJ, key);
+        return env->NewStringUTF("green");
+    }
+    env->ReleaseStringUTFChars(keyJ, key);
     jstring ret = defJ;
```

---

## Approach B: Binary ASM Patching (For Stock OEM ROMs)

On OEM stock ROMs (Samsung OneUI, LG UX, Xiaomi HyperOS, ColorOS), manufacturer source code is unavailable.  
We implement the exact same logic directly at the native machine-code level (**ARM64 AArch64** & **ARM32 ARMv7-a / Thumb-2**) using **Code Cave injection** in `libc.so`.

Standalone hook reference implementations are available in [`hooks/`](hooks/):
1. **[`hooks/hook_property_get_arm32_thumb.py`](hooks/hook_property_get_arm32_thumb.py):** Intercepts `__system_property_get` on **ARMv7-a 32-bit** (Thumb-2 mode using `movw`/`movt` word loads).
2. **[`hooks/hook_property_get_and_openat.py`](hooks/hook_property_get_and_openat.py):** Intercepts `__system_property_get` on **ARM64** and redirects `/proc/cmdline` via `openat`.
3. **[`hooks/hook_property_read_callback.py`](hooks/hook_property_read_callback.py):** Intercepts Bionic's internal callback invocation (`blr x19`) on **ARM64**.

### Automated Patcher Usage
`patcher.py` automatically detects bitness and architecture (ELF32/Thumb-2 vs. ELF64/AArch64), parses `.dynsym`, allocates an aligned code cave, and applies the appropriate branch.

```bash
pip install -r requirements.txt

# 1. Pull libc.so from device via TWRP/ADB:
# For 64-bit devices (ARM64):
adb shell "cp /system/apex/com.android.runtime/lib64/bionic/libc.so /sdcard/libc.so || cp /system/lib64/libc.so /sdcard/libc.so"
adb pull /sdcard/libc.so ./libc.so

# For 32-bit legacy devices (ARMv7-a, e.g. Galaxy J4+, Redmi 4A):
adb shell "cp /system/apex/com.android.runtime/lib/bionic/libc.so /sdcard/libc.so || cp /system/lib/libc.so /sdcard/libc.so"
adb pull /sdcard/libc.so ./libc.so

# 2. Patch binary:
python patcher.py libc.so -o libc_patched.so

# 3. Flash back to device via TWRP:
./deploy_twrp.sh
```

---

## Verification

Run the test script on device:
```bash
adb push verify_props.sh /data/local/tmp/
adb shell "sh /data/local/tmp/verify_props.sh"
```

```text
=========================================
   Bionic FakeLock Verification Check
=========================================
[PASS] ro.boot.flash.locked = '1'
[PASS] ro.boot.verifiedbootstate = 'green'
[PASS] ro.boot.vbmeta.device_state = 'locked'
=========================================
```

---

## Android 16 & 17 Compatibility

- **Core NDK ABI Stability:** `<sys/system_properties.h>` ABI remains mandatory across all Android versions.
- **16KB Page Size (Android 15 / 16 / 17):** `patcher.py` automatically reads `p_align` from ELF headers and aligns code caves to `0x4000`.
- **ARMv9 BTI & PAC:** Uses relative direct branches (`B`) and preserves `autiasp`/`paciasp` landing pads.

---

## Author & License
Author: **Le Thanh Hoan** (`thhoannday@gmail.com`)  
License: GNU General Public License v3.0 (GPLv3).
