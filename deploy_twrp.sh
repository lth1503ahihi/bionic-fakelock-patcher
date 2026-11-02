#!/bin/bash
# =============================================================================
# Bionic FakeLock TWRP Deployment Script
# Targets:
#   1. Flattened APEX: /system_root/system/apex/com.android.runtime/lib64/bionic/libc.so
#   2. System Lib64:   /system_root/system/lib64/libc.so
# =============================================================================

set -e

echo "[+] Bionic FakeLock Installer starting..."

PATCHED_LIBC="./libc_patched.so"

if [ ! -f "$PATCHED_LIBC" ]; then
    echo "[-] Error: $PATCHED_LIBC not found on host!"
    exit 1
fi

echo "[+] Waiting for device in Recovery mode (TWRP)..."
adb wait-for-recovery

echo "[+] Mounting system partition..."
adb shell "mount -o rw /system_root || mount -o rw /system"

TARGET_APEX="/system_root/system/apex/com.android.runtime/lib64/bionic/libc.so"
TARGET_SYS="/system_root/system/lib64/libc.so"

echo "[+] Creating backup on device..."
adb shell "[ -f $TARGET_APEX ] && cp $TARGET_APEX ${TARGET_APEX}.bak"
adb shell "[ -f $TARGET_SYS ] && cp $TARGET_SYS ${TARGET_SYS}.bak"

echo "[+] Pushing patched libc.so..."
adb push "$PATCHED_LIBC" /tmp/libc_patched.so

echo "[+] Installing to APEX Runtime..."
adb shell "cp /tmp/libc_patched.so $TARGET_APEX"
adb shell "chmod 644 $TARGET_APEX"
adb shell "chown root:root $TARGET_APEX"

echo "[+] Installing to System lib64..."
adb shell "cp /tmp/libc_patched.so $TARGET_SYS"
adb shell "chmod 644 $TARGET_SYS"
adb shell "chown root:root $TARGET_SYS"

echo "[+] Syncing filesystems..."
adb shell "sync"

echo "[+] Verification:"
adb shell "ls -l $TARGET_APEX"
adb shell "ls -l $TARGET_SYS"

echo "[+] DEPLOYMENT COMPLETE! Rebooting system..."
adb reboot
