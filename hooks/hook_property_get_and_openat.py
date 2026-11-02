#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
Hook 2: Intercepting __system_property_get & openat (/proc/cmdline redirect)
=============================================================================
Architecture: ARM64 (AArch64 Little-Endian)
Target: Bionic libc.so exported public functions

Mechanism:
  1. __system_property_get(const char* name, char* value):
     - x0: property name pointer
     - x1: destination value buffer
     Intercepts entry:
     - "ro.boot.flash.locked"        -> writes "1\0" into [x1], returns length 1
     - "ro.boot.verifiedbootstate"   -> writes "green\0" into [x1], returns length 5
     - "ro.boot.vbmeta.device_state" -> writes "locked\0" into [x1], returns length 6
     - Non-matching: executes original relocated prologue and jumps back.

  2. openat(int dirfd, const char* pathname, int flags, ...):
     - x1: pathname pointer
     Intercepts entry:
     - If pathname == "/proc/cmdline": redirects x1 to "/system/etc/cmdline"
       where a clean cmdline ("androidboot.verifiedbootstate=green") resides.
     - Non-matching: executes original syscall and proceeds.
=============================================================================
"""

import struct
import keystone

ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

HOOK_GET_ADDR = 0xC1960
TARGET_GET_RET = 0x50EAC

HOOK_OPENAT_ADDR = 0xC1AA0
TARGET_OPENAT_RET = 0x5D770

ASM_PROPERTY_GET = """
    cbz x0, orig_get

    // Check prefix 'ro.boot.'
    ldr x2, [x0]
    adr x3, c_ro_boot_g
    ldr x3, [x3]
    cmp x2, x3
    b.eq check_boot_props_g

    b orig_get

check_boot_props_g:
    // Check 'flash.locked'
    ldr x2, [x0, #8]
    adr x3, c_flash_lo_g
    ldr x3, [x3]
    cmp x2, x3
    b.ne check_verified_g

    ldr w2, [x0, #16]
    adr x3, c_cked_g
    ldr w3, [x3]
    cmp w2, w3
    b.ne check_verified_g
    ldrb w2, [x0, #20]
    cbnz w2, check_verified_g

    // Override: "1\\0"
    mov w2, #0x31
    strh w2, [x1]
    mov w0, #1
    ret

check_verified_g:
    // Check 'verifiedbootstate'
    adr x3, c_verified_g
    ldr x3, [x3]
    cmp x2, x3
    b.ne check_vbmeta_g

    ldr x2, [x0, #16]
    adr x3, c_bootstat_g
    ldr x3, [x3]
    cmp x2, x3
    b.ne check_vbmeta_g

    ldrh w2, [x0, #24]
    cmp w2, #0x65
    b.ne check_vbmeta_g

    // Override: "green\\0"
    mov w2, #0x7267
    movk w2, #0x6565, lsl #16
    str w2, [x1]
    mov w2, #0x6e
    strh w2, [x1, #4]
    mov w0, #5
    ret

check_vbmeta_g:
    // Check 'vbmeta.device_state'
    adr x3, c_vbmeta_g
    ldr x3, [x3]
    cmp x2, x3
    b.ne orig_get

    ldr x2, [x0, #16]
    adr x3, c_dev_state_g
    ldr x3, [x3]
    cmp x2, x3
    b.ne orig_get

    ldrh w2, [x0, #24]
    cmp w2, #0x65
    b.ne orig_get

    // Override: "locked\\0"
    mov w2, #0x6f6c
    movk w2, #0x6b63, lsl #16
    str w2, [x1]
    mov w2, #0x6465
    strh w2, [x1, #4]
    mov w0, #6
    ret

orig_get:
    // Relocated original prologue
    adrp x8, #0xc9000
    add x8, x8, #0x3d0
    mov x2, x1
    mov x1, x0
    mov x0, x8
    b target_get

.p2align 3
c_ro_boot_g:    .quad 0x2e746f6f622e6f72
c_flash_lo_g:   .quad 0x6f6c2e6873616c66
c_cked_g:       .int  0x64656b63
c_verified_g:   .quad 0x6465696669726576
c_bootstat_g:   .quad 0x74617473746f6f62
c_vbmeta_g:     .quad 0x65642e6174656d62
c_dev_state_g:  .quad 0x74735f65636976

.p2align 2
target_get:
"""

ASM_OPENAT = """
    cbz x1, orig_openat

    // Check string "/proc/cmdline"
    ldr x4, [x1]
    adr x5, c_proc_cmdline_1
    ldr x5, [x5]
    cmp x4, x5
    b.ne orig_openat

    ldr w4, [x1, #8]
    adr x5, c_proc_cmdline_2
    ldr w5, [x5]
    cmp w4, w5
    b.ne orig_openat

    ldrh w4, [x1, #12]
    cbnz w4, orig_openat

    // Redirect to clean fake cmdline
    adr x1, str_fake_cmdline

orig_openat:
    .int 0xd503233f     // paciasp / original instruction
    b target_openat

.p2align 3
c_proc_cmdline_1:   .quad 0x6d632f636f72702f    // '/proc/cm'
c_proc_cmdline_2:   .int  0x656e696c            // 'dlin'

str_fake_cmdline:   .asciz "/system/etc/cmdline"

.p2align 2
target_openat:
"""

def compile_get_hook(hook_addr=HOOK_GET_ADDR, ret_addr=TARGET_GET_RET):
    enc, _ = ks.asm(ASM_PROPERTY_GET, hook_addr)
    b_from = hook_addr + len(enc)
    off = (ret_addr - b_from) // 4
    inst = struct.pack('<I', 0x14000000 | (off & 0x03ffffff))
    return bytearray(enc) + inst

def compile_openat_hook(hook_addr=HOOK_OPENAT_ADDR, ret_addr=TARGET_OPENAT_RET):
    enc, _ = ks.asm(ASM_OPENAT, hook_addr)
    b_from = hook_addr + len(enc)
    off = (ret_addr - b_from) // 4
    inst = struct.pack('<I', 0x14000000 | (off & 0x03ffffff))
    return bytearray(enc) + inst

if __name__ == '__main__':
    get_bytes = compile_get_hook()
    openat_bytes = compile_openat_hook()
    print(f"[+] Compiled __system_property_get hook: {len(get_bytes)} bytes.")
    print(f"[+] Compiled openat redirect hook:       {len(openat_bytes)} bytes.")
