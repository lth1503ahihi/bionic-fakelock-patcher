# Bionic FakeLock Patcher

[English](README.md) | [Tiếng Việt](README_VI.md)

Giải pháp FakeLock và giả lập trạng thái Bootloader toàn diện cho Android ARM64 & ARM32 (AArch64) & ARM32 (ARMv7-a Thumb-2).  
Cung cấp đồng thời cả **2 bản vá mã nguồn C/C++** (dành cho người tự build Custom ROM / AOSP) và **Công cụ vá nhị phân Assembly** (dành cho ROM Stock của hãng không có mã nguồn).

Chặn và giả lập trực tiếp các thuộc tính Bootloader Locked ở tầng native, hoàn toàn **KHÔNG CẦN ROOT** (không dùng Magisk, KernelSU, Zygisk).

---

## 2 Hướng tiếp cận: Build từ Source vs Vá Nhị Phân (Binary Patching)

Tùy vào việc bạn đang tự build ROM từ mã nguồn hay đang mod trên ROM Stock nguyên bản của nhà sản xuất, repo này cung cấp 2 giải pháp độc lập:

```
                          ┌───────────────────────────┐
                          │   Android Bootloader      │
                          │   Unlocked (ro.boot.*)    │
                          └─────────────┬─────────────┘
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼                                                     ▼
   [Cách 1: Có Mã Nguồn]                                 [Cách 2: ROM Stock Hãng]
   Tự biên dịch ROM AOSP / LineageOS                     Không có source code / File ELF bị strip
   Áp dụng 2 bản vá Git C/C++                            Vá thẳng Assembly qua Code Cave
   ├── bionic (libc)                                    ├── patcher.py (Tự động)
   └── frameworks/base (JNI)                            └── Tiêm mã máy ARM64
             │                                                     │
             └──────────────────────────┬──────────────────────────┘
                                        ▼
                          ┌───────────────────────────┐
                          │ ro.boot.flash.locked = 1  │
                          │ verifiedbootstate = green │
                          │ vbmeta.device_state=locked│
                          │   Vượt 100% app ngân hàng │
                          └───────────────────────────┘
```

---

## Cách 1: Bản vá mã nguồn C/C++ (Dành cho Dev build ROM)

Nếu bạn có mã nguồn AOSP, LineageOS hoặc Custom ROM, áp dụng 2 file patch trong thư mục [`patches/`](patches/):

### 1. Bản vá Bionic C Library
File: [`patches/0001-bionic-fake-bootloader-locked.patch`](patches/0001-bionic-fake-bootloader-locked.patch)  
Đích: `bionic/libc/system_properties/system_properties.cpp`  

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

### 2. Bản vá Framework JNI
File: [`patches/0002-frameworks-base-fake-bootloader-locked.patch`](patches/0002-frameworks-base-fake-bootloader-locked.patch)  
Đích: `frameworks/base/core/jni/android_os_SystemProperties.cpp`  

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

## Cách 2: Vá Nhị Phân Assembly (Dành cho ROM Stock của Hãng)

Trên các bản ROM Stock đóng kín (Samsung OneUI, LG UX, Xiaomi HyperOS, ColorOS...), bạn không có mã nguồn để build.  
Chúng ta tái hiện chính xác logic trên bằng cách tiêm trực tiếp mã máy (**ARM64 AArch64** & **ARM32 ARMv7-a / Thumb-2**) vào **Code Cave** của file nhị phân `libc.so`.

Các đoạn mã hook mẫu nằm trong thư mục [`hooks/`](hooks/):
1. **[`hooks/hook_property_get_arm32_thumb.py`](hooks/hook_property_get_arm32_thumb.py):** Hook `__system_property_get` cho **ARMv7-a 32-bit** (chế độ Thumb-2 với kỹ thuật load word `movw`/`movt`).
2. **[`hooks/hook_property_get_and_openat.py`](hooks/hook_property_get_and_openat.py):** Hook `__system_property_get` cho **ARM64** và chuyển hướng `/proc/cmdline` qua `openat`.
3. **[`hooks/hook_property_read_callback.py`](hooks/hook_property_read_callback.py):** Hook trực tiếp tại hàm callback nội bộ (`blr x19`) của Bionic trên **ARM64**.

### Sử dụng công cụ tự động
`patcher.py` tự động nhận diện kiến trúc (ELF32/Thumb-2 hay ELF64/AArch64), phân giải `.dynsym`, cấp phát Code Cave chuẩn alignment và tiêm lệnh nhảy thích hợp.

```bash
pip install -r requirements.txt

# 1. Trích xuất libc.so từ máy qua TWRP:
# Đối với máy 64-bit (ARM64):
adb shell "cp /system/apex/com.android.runtime/lib64/bionic/libc.so /sdcard/libc.so || cp /system/lib64/libc.so /sdcard/libc.so"
adb pull /sdcard/libc.so ./libc.so

# Đối với máy 32-bit (ARMv7-a, ví dụ Galaxy J4+, Redmi 4A):
adb shell "cp /system/apex/com.android.runtime/lib/bionic/libc.so /sdcard/libc.so || cp /system/lib/libc.so /sdcard/libc.so"
adb pull /sdcard/libc.so ./libc.so

# 2. Chạy patch tự động:
python patcher.py libc.so -o libc_patched.so

# 3. Nạp lại vào máy:
./deploy_twrp.sh
```

---

## Kiểm tra sau khi nạp

Chạy script test trên thiết bị:
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

Tất cả app ngân hàng (VNeID CA-E006, Techcombank, VIB mã lỗi 6...) sẽ nhận diện bootloader là **Đã Khóa** và mở bình thường.

---

## Tương thích Android 16 & 17

- **Tính bất biến của NDK ABI:** Giao diện `<sys/system_properties.h>` là nền tảng cốt lõi của Android, Google không thể thay đổi.
- **Hỗ trợ Kernel 16KB Page Size (Android 15 / 16 / 17):** `patcher.py` tự động đọc `p_align` từ Program Header của ELF để căn chỉnh Code Cave theo chuẩn 16KB (`0x4000`), không gây lỗi `ELF alignment error`.
- **Bảo mật phần cứng ARMv9:** Sử dụng lệnh nhảy tương đối `B` và bảo toàn chỉ lệnh `autiasp` / `paciasp`, không kích hoạt ngắt `SIGILL` của CPU.

---

## Tác giả & Giấy phép
Tác giả: **Le Thanh Hoan** (`thhoannday@gmail.com`)  
Giấy phép: GNU General Public License v3.0 (GPLv3).
