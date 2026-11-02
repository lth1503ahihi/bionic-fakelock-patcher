#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
Hook: Intercepting __system_property_get on ARMv7-a (32-bit / Thumb-2)
=============================================================================
Architecture: ARMv7-a 32-bit (Thumb-2 Mode)
Target: /system/lib/libc.so on 32-bit devices (e.g., Galaxy J4+, J6+, Redmi 4A)
        and 32-bit multilib runtime on 64-bit devices.

Calling Convention (AAPCS):
  r0 = const char* name
  r1 = char* value (output buffer)
  Return value in r0 = length of property value string.

Mechanism:
  Checks property name in r0 via 32-bit word loads:
  1. Checks prefix 'ro.b' (0x622e6f72) and 'oot.' (0x2e746f6f)
  2. If matched:
     - 'flash.locked'        -> writes "1\0" into [r1], returns 1
     - 'verifiedbootstate'   -> writes "green\0" into [r1], returns 5
     - 'vbmeta.device_state' -> writes "locked\0" into [r1], returns 6
  3. Non-matching properties:
     - Jumps to original libc implementation.
=============================================================================
"""

import keystone

ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)

HOOK_ADDR = 0x40000
ORIG_TARGET = 0x30124

ASM_THUMB2 = """
    cbz r0, orig_get

    // 1. Check 'ro.b' (0x622e6f72)
    ldr r2, [r0]
    movw r3, #0x6f72
    movt r3, #0x622e
    cmp r2, r3
    bne orig_get

    // 2. Check 'oot.' (0x2e746f6f)
    ldr r2, [r0, #4]
    movw r3, #0x6f6f
    movt r3, #0x2e74
    cmp r2, r3
    bne orig_get

check_flash:
    // Check 'flas' (0x73616c66)
    ldr r2, [r0, #8]
    movw r3, #0x6c66
    movt r3, #0x7361
    cmp r2, r3
    bne check_verified

    // Check 'h.lo' (0x6f6c2e68)
    ldr r2, [r0, #12]
    movw r3, #0x2e68
    movt r3, #0x6f6c
    cmp r2, r3
    bne check_verified

    // Check 'cked' (0x64656b63)
    ldr r2, [r0, #16]
    movw r3, #0x6b63
    movt r3, #0x6465
    cmp r2, r3
    bne check_verified

    // Check null terminator at byte 20
    ldrb r2, [r0, #20]
    cbnz r2, check_verified

    // ro.boot.flash.locked -> '1\\0'
    movs r2, #0x31
    strb r2, [r1]
    movs r2, #0
    strb r2, [r1, #1]
    movs r0, #1
    bx lr

check_verified:
    // Check 'veri' (0x69726576)
    ldr r2, [r0, #8]
    movw r3, #0x6576
    movt r3, #0x6972
    cmp r2, r3
    bne check_vbmeta

    // Check 'fied' (0x64656966)
    ldr r2, [r0, #12]
    movw r3, #0x6966
    movt r3, #0x6465
    cmp r2, r3
    bne check_vbmeta

    // Check 'boot' (0x746f6f62)
    ldr r2, [r0, #16]
    movw r3, #0x6f62
    movt r3, #0x746f
    cmp r2, r3
    bne check_vbmeta

    // Check 'stat' (0x74617473)
    ldr r2, [r0, #20]
    movw r3, #0x7473
    movt r3, #0x7461
    cmp r2, r3
    bne check_vbmeta

    // Check 'e\\0' (0x0065)
    ldrh r2, [r0, #24]
    cmp r2, #0x65
    bne check_vbmeta

    // ro.boot.verifiedbootstate -> 'green\\0'
    movw r2, #0x7267
    movt r2, #0x6565
    str r2, [r1]
    movs r2, #0x6e
    strb r2, [r1, #4]
    movs r2, #0
    strb r2, [r1, #5]
    movs r0, #5
    bx lr

check_vbmeta:
    // Check 'vbme' (0x656d6276)
    ldr r2, [r0, #8]
    movw r3, #0x656d
    movt r3, #0x6562
    cmp r2, r3
    bne orig_get

    // Check 'ta.d' (0x642e6174)
    ldr r2, [r0, #12]
    movw r3, #0x6174
    movt r3, #0x642e
    cmp r2, r3
    bne orig_get

    // Check 'evic' (0x63697665)
    ldr r2, [r0, #16]
    movw r3, #0x7665
    movt r3, #0x6369
    cmp r2, r3
    bne orig_get

    // ro.boot.vbmeta.device_state -> 'locked\\0'
    movw r2, #0x6f6c
    movt r2, #0x6b63
    str r2, [r1]
    movs r2, #0x64
    strb r2, [r1, #4]
    movs r2, #0x65
    strb r2, [r1, #5]
    movs r2, #0
    strb r2, [r1, #6]
    movs r0, #6
    bx lr

orig_get:
    movw r3, #0x0124
    movt r3, #0x0003
    bx r3
"""

def compile_thumb2_hook(hook_addr=HOOK_ADDR, target_after_hook=ORIG_TARGET):
    asm = ASM_THUMB2.replace("movw r3, #0x0124\n    movt r3, #0x0003",
                             f"movw r3, #{hex(target_after_hook & 0xffff)}\n    movt r3, #{hex((target_after_hook >> 16) & 0xffff)}")
    enc, count = ks.asm(asm, hook_addr)
    return bytearray(enc)

if __name__ == '__main__':
    hook_bytes = compile_thumb2_hook()
    print(f"[+] Compiled ARM32 (Thumb-2) Hook: {len(hook_bytes)} bytes.")
