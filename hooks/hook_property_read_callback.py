#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
Hook 1: Intercepting SystemProperties::Read / __system_property_read_callback
=============================================================================
Architecture: ARM64 (AArch64 Little-Endian)
Target: Bionic libc.so internal callback invocation

Mechanism:
    Right before Bionic calls the user callback via `blr x19`, registers hold:
      - x20: cookie / context pointer
      - x21: pointer to prop_info (holds property name string)
      - x2:  pointer to property value string
    This hook intercepts the call, checks if [x21] matches target boot properties:
      - "ro.boot.flash.locked"      -> overrides x2 to point to "1"
      - "ro.boot.verifiedbootstate" -> overrides x2 to point to "green"
    Then invokes `blr x19` and returns cleanly back to libc.
=============================================================================
"""

import struct
import keystone

ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

# Example address in Code Cave and return target in libc.so
HOOK_ADDR = 0xC1840
RET_ADDR = 0x50E78

ASM_READ_CALLBACK = """
    // Load property name pointer from prop_info [x21]
    ldr x4, [x21]

    // Check prefix 'ro.boot.'
    adr x5, c_ro_boot
    ldr x5, [x5]
    cmp x4, x5
    b.eq check_boot_props

    // Not matching -> jump straight to original callback invocation
    b done

check_boot_props:
    // Check 'flash.locked'
    ldr x4, [x21, #8]
    adr x5, c_flash_lo
    ldr x5, [x5]
    cmp x4, x5
    b.ne check_verified

    ldr w4, [x21, #16]
    adr x5, c_cked
    ldr w5, [x5]
    cmp w4, w5
    b.ne check_verified
    ldrb w4, [x21, #20]
    cbnz w4, check_verified

    // Override value pointer x2 -> "1"
    adr x2, val_locked
    b done

check_verified:
    // Check 'verifiedbootstate'
    adr x5, c_verified
    ldr x5, [x5]
    cmp x4, x5
    b.ne done

    ldr x4, [x21, #16]
    adr x5, c_bootstat
    ldr x5, [x5]
    cmp x4, x5
    b.ne done
    ldrh w4, [x21, #24]
    cmp w4, #0x65
    b.ne done

    // Override value pointer x2 -> "green"
    adr x2, val_green

done:
    // Restore registers and invoke original callback
    mov x0, x20
    mov x1, x21
    blr x19
    b return_to_libc

.p2align 3
c_ro_boot:      .quad 0x2e746f6f622e6f72    // 'ro.boot.'
c_flash_lo:     .quad 0x6f6c2e6873616c66    // 'flash.lo'
c_cked:         .word 0x64656b63            // 'cked'
c_verified:     .quad 0x6465696669726576    // 'verified'
c_bootstat:     .quad 0x74617473746f6f62    // 'bootstat'

val_locked:     .asciz "1"
val_green:      .asciz "green"

.p2align 2
return_to_libc:
"""

def compile_hook(hook_addr=HOOK_ADDR, ret_addr=RET_ADDR):
    encoding, count = ks.asm(ASM_READ_CALLBACK, hook_addr)
    hook_bytes = bytearray(encoding)
    branch_from = hook_addr + len(hook_bytes)
    offset = (ret_addr - branch_from) // 4
    branch_inst = struct.pack('<I', 0x14000000 | (offset & 0x03ffffff))
    hook_bytes.extend(branch_inst)
    return hook_bytes

if __name__ == '__main__':
    code = compile_hook()
    print(f"[+] Compiled Read Callback Hook: {len(code)} bytes.")
