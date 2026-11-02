#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Android Bionic FakeLock Patcher (ARM64 & ARM32)
Description:
    Automated zero-root binary patcher for Android Bionic C library (libc.so).
    Supports both 64-bit (AArch64) and 32-bit (ARMv7-a / Thumb-2).
    Transparently intercepts property lookups to spoof:
      - ro.boot.flash.locked        -> "1"
      - ro.boot.verifiedbootstate   -> "green"
      - ro.boot.vbmeta.device_state -> "locked"
"""

import os
import sys
import struct
import argparse

try:
    import keystone
except ImportError:
    print("[-] Error: 'keystone-engine' is required. Run: pip install keystone-engine")
    sys.exit(1)

try:
    import capstone
except ImportError:
    print("[-] Error: 'capstone' is required. Run: pip install capstone")
    sys.exit(1)


class BionicPatcher:
    def __init__(self, libc_path, verbose=True):
        self.libc_path = libc_path
        self.verbose = verbose
        with open(libc_path, 'rb') as f:
            self.data = bytearray(f.read())

        self._detect_arch()
        self._init_engines()
        self._parse_elf()

    def log(self, msg):
        if self.verbose:
            print(f"[+] {msg}")

    def _detect_arch(self):
        """Identify ELF bitness and machine architecture"""
        assert self.data[:4] == b'\x7fELF', "Invalid ELF magic header!"
        ei_class = self.data[4]
        e_machine = struct.unpack('<H', self.data[18:20])[0]

        if ei_class == 2 and e_machine == 183:  # ELFCLASS64, EM_AARCH64
            self.is_64 = True
            self.arch_name = "ARM64 (AArch64)"
        elif ei_class == 1 and e_machine == 40:  # ELFCLASS32, EM_ARM
            self.is_64 = False
            self.arch_name = "ARM32 (ARMv7-a / Thumb-2)"
        else:
            raise ValueError(f"Unsupported architecture: class={ei_class}, machine={e_machine}")

        self.log(f"Detected target architecture: {self.arch_name}")

    def _init_engines(self):
        """Initialize Keystone and Capstone for detected architecture"""
        if self.is_64:
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
            self.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
            self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

    def _parse_elf(self):
        """Parse ELF Program Headers and find executable segments"""
        if self.is_64:
            phoff = struct.unpack('<Q', self.data[32:40])[0]
            phentsize = struct.unpack('<H', self.data[54:56])[0]
            phnum = struct.unpack('<H', self.data[56:58])[0]
        else:
            phoff = struct.unpack('<I', self.data[28:32])[0]
            phentsize = struct.unpack('<H', self.data[42:44])[0]
            phnum = struct.unpack('<H', self.data[44:46])[0]

        self.rx_segments = []
        for i in range(phnum):
            off = phoff + i * phentsize
            ph = self.data[off : off + phentsize]
            if self.is_64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack('<IIQQQQQQ', ph)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack('<IIIIIIII', ph)

            if p_type == 1 and (p_flags & 1):  # PT_LOAD & PF_X
                self.rx_segments.append({
                    'offset': p_offset,
                    'vaddr': p_vaddr,
                    'filesz': p_filesz,
                    'align': p_align
                })

        self.log(f"Found {len(self.rx_segments)} executable (RX) segment(s).")

    def find_code_cave(self, needed_size=512):
        """Locate trailing null-byte code cave in executable segments"""
        align_boundary = 16 if self.is_64 else 4
        for seg in self.rx_segments:
            p_offset = seg['offset']
            p_filesz = seg['filesz']
            seg_data = self.data[p_offset : p_offset + p_filesz]

            zero_count = 0
            for j in range(len(seg_data) - 1, -1, -1):
                if seg_data[j] == 0:
                    zero_count += 1
                else:
                    if zero_count >= needed_size:
                        cave_start = j + 1
                        aligned_start = (cave_start + (align_boundary - 1)) & ~(align_boundary - 1)
                        cave_offset = p_offset + aligned_start
                        self.log(f"Code cave allocated at offset: 0x{cave_offset:X} (Size: {zero_count} bytes)")
                        return cave_offset
                    zero_count = 0
        return None

    def find_symbol_offset(self, sym_name):
        """Locate exported symbol via .dynsym"""
        if self.is_64:
            shoff = struct.unpack('<Q', self.data[40:48])[0]
            shentsize = struct.unpack('<H', self.data[58:60])[0]
            shnum = struct.unpack('<H', self.data[60:62])[0]
        else:
            shoff = struct.unpack('<I', self.data[32:36])[0]
            shentsize = struct.unpack('<H', self.data[46:48])[0]
            shnum = struct.unpack('<H', self.data[48:50])[0]

        dynsym_hdr = None
        for i in range(shnum):
            off = shoff + i * shentsize
            if self.is_64:
                sh_name, sh_type, _, _, sh_offset, sh_size, sh_link, _, _, sh_entsize = struct.unpack('<IIQQQQIIQQ', self.data[off:off+64])
            else:
                sh_name, sh_type, _, _, sh_offset, sh_size, sh_link, _, _, sh_entsize = struct.unpack('<IIIIIIIIII', self.data[off:off+40])

            if sh_type == 11:  # SHT_DYNSYM
                dynsym_hdr = (sh_offset, sh_size, sh_entsize, sh_link)
                break

        if dynsym_hdr:
            str_idx = dynsym_hdr[3]
            off_str = shoff + str_idx * shentsize
            if self.is_64:
                _, _, _, _, str_offset, str_size, _, _, _, _ = struct.unpack('<IIQQQQIIQQ', self.data[off_str:off_str+64])
            else:
                _, _, _, _, str_offset, str_size, _, _, _, _ = struct.unpack('<IIIIIIIIII', self.data[off_str:off_str+40])

            strtab = self.data[str_offset : str_offset + str_size]
            sym_off, sym_size, sym_entsize, _ = dynsym_hdr
            num_syms = sym_size // sym_entsize

            for j in range(num_syms):
                entry_off = sym_off + j * sym_entsize
                if self.is_64:
                    st_name, _, _, _, st_value, _ = struct.unpack('<IBBHQQ', self.data[entry_off:entry_off+24])
                else:
                    st_name, st_value, _, _, _, _ = struct.unpack('<IIIBBH', self.data[entry_off:entry_off+16])

                end = strtab.find(b'\x00', st_name)
                name = strtab[st_name:end].decode('ascii', errors='ignore')
                if name == sym_name:
                    # In Thumb, bit 0 is set (clear for instruction offset)
                    return st_value & ~1
        return None

    def find_system_property_get(self):
        """Locate __system_property_get entry address"""
        sym_addr = self.find_symbol_offset('__system_property_get')
        if sym_addr:
            self.log(f"Located __system_property_get via .dynsym at 0x{sym_addr:X}")
            return sym_addr

        # Fallback for ARM64 pattern
        if self.is_64:
            pattern = bytes([0xe2, 0x03, 0x01, 0xaa, 0xe1, 0x03, 0x00, 0xaa])
            pos = 0
            while True:
                idx = self.data.find(pattern, pos)
                if idx == -1:
                    break
                return idx - 8
        return None

    def generate_arm64_hook(self, target_after_hook):
        return f"""
        cbz x0, orig_get
        ldr x2, [x0]
        adr x3, c_ro_boot_g
        ldr x3, [x3]
        cmp x2, x3
        b.ne orig_get

        // flash.locked
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
        mov w2, #0x31
        strh w2, [x1]
        mov w0, #1
        ret

    check_verified_g:
        // verifiedbootstate
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
        mov w2, #0x7267
        movk w2, #0x6565, lsl #16
        str w2, [x1]
        mov w2, #0x6e
        strh w2, [x1, #4]
        mov w0, #5
        ret

    check_vbmeta_g:
        // vbmeta.device_state
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
        mov w2, #0x6f6c
        movk w2, #0x6b63, lsl #16
        str w2, [x1]
        mov w2, #0x6465
        strh w2, [x1, #4]
        mov w0, #6
        ret

    orig_get:
        mov x2, x1
        mov x1, x0
        ldr x0, [sp]
        b 0x{target_after_hook:X}

    .p2align 3
    c_ro_boot_g:    .quad 0x2e746f6f622e6f72
    c_flash_lo_g:   .quad 0x6f6c2e6873616c66
    c_cked_g:       .int  0x64656b63
    c_verified_g:   .quad 0x6465696669726576
    c_bootstat_g:   .quad 0x74617473746f6f62
    c_vbmeta_g:     .quad 0x65642e6174656d62
    c_dev_state_g:  .quad 0x74735f65636976
        """

    def generate_arm32_hook(self, target_after_hook):
        low_w = target_after_hook & 0xffff
        high_w = (target_after_hook >> 16) & 0xffff
        return f"""
        cbz r0, orig_get

        // Check 'ro.b' and 'oot.'
        ldr r2, [r0]
        movw r3, #0x6f72
        movt r3, #0x622e
        cmp r2, r3
        bne orig_get

        ldr r2, [r0, #4]
        movw r3, #0x6f6f
        movt r3, #0x2e74
        cmp r2, r3
        bne orig_get

    check_flash:
        // 'flash.locked'
        ldr r2, [r0, #8]
        movw r3, #0x6c66
        movt r3, #0x7361
        cmp r2, r3
        bne check_verified
        ldr r2, [r0, #12]
        movw r3, #0x2e68
        movt r3, #0x6f6c
        cmp r2, r3
        bne check_verified
        ldr r2, [r0, #16]
        movw r3, #0x6b63
        movt r3, #0x6465
        cmp r2, r3
        bne check_verified
        ldrb r2, [r0, #20]
        cbnz r2, check_verified

        // Output: '1\\0'
        movs r2, #0x31
        strb r2, [r1]
        movs r2, #0
        strb r2, [r1, #1]
        movs r0, #1
        bx lr

    check_verified:
        // 'verifiedbootstate'
        ldr r2, [r0, #8]
        movw r3, #0x6576
        movt r3, #0x6972
        cmp r2, r3
        bne check_vbmeta
        ldr r2, [r0, #12]
        movw r3, #0x6966
        movt r3, #0x6465
        cmp r2, r3
        bne check_vbmeta
        ldr r2, [r0, #16]
        movw r3, #0x6f62
        movt r3, #0x746f
        cmp r2, r3
        bne check_vbmeta
        ldr r2, [r0, #20]
        movw r3, #0x7473
        movt r3, #0x7461
        cmp r2, r3
        bne check_vbmeta
        ldrh r2, [r0, #24]
        cmp r2, #0x65
        bne check_vbmeta

        // Output: 'green\\0'
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
        // 'vbmeta.device_state'
        ldr r2, [r0, #8]
        movw r3, #0x656d
        movt r3, #0x6562
        cmp r2, r3
        bne orig_get
        ldr r2, [r0, #12]
        movw r3, #0x6174
        movt r3, #0x642e
        cmp r2, r3
        bne orig_get
        ldr r2, [r0, #16]
        movw r3, #0x7665
        movt r3, #0x6369
        cmp r2, r3
        bne orig_get

        // Output: 'locked\\0'
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
        movw r3, #{hex(low_w)}
        movt r3, #{hex(high_w)}
        bx r3
        """

    def apply_branch(self, from_addr, to_addr):
        """Construct architecture-specific branch instruction"""
        if self.is_64:
            delta = (to_addr - from_addr) // 4
            inst = struct.pack('<I', 0x14000000 | (delta & 0x03ffffff))
            self.data[from_addr : from_addr + 4] = inst
        else:
            # Thumb-2 32-bit branch: B.W to_addr
            enc, _ = self.ks.asm(f"b.w 0x{to_addr:X}", from_addr)
            self.data[from_addr : from_addr + len(enc)] = bytearray(enc)

    def patch(self, output_path):
        self.log(f"Starting Bionic FakeLock patch for {self.arch_name}...")

        get_target = self.find_system_property_get()
        if not get_target:
            get_target = 0x50EAC if self.is_64 else 0x30124
            self.log(f"Falling back to default offset: 0x{get_target:X}")

        cave = self.find_code_cave(needed_size=512)
        if not cave:
            cave = 0xC1960 if self.is_64 else 0x50000
            self.log(f"Falling back to default code cave: 0x{cave:X}")

        step = 4 if self.is_64 else 2
        if self.is_64:
            asm_code = self.generate_arm64_hook(get_target + step)
        else:
            # In Thumb, target address must have LSB=1
            asm_code = self.generate_arm32_hook((get_target + 4) | 1)

        encoding, count = self.ks.asm(asm_code, cave)
        hook_bytes = bytearray(encoding)
        self.log(f"Assembled {self.arch_name} hook: {len(hook_bytes)} bytes ({count} instructions).")

        self.data[cave : cave + len(hook_bytes)] = hook_bytes
        self.apply_branch(get_target, cave)
        self.log(f"Patched __system_property_get: 0x{get_target:X} -> 0x{cave:X}")

        with open(output_path, 'wb') as f:
            f.write(self.data)

        self.log(f"Patched libc saved to: {output_path}")
        self.log(f"File size intact: {len(self.data)} bytes")


def main():
    parser = argparse.ArgumentParser(
        description="Universal Android Bionic FakeLock Patcher (ARM64 & ARM32)"
    )
    parser.add_argument("input", help="Path to libc.so extracted from device (ARM64 or ARM32)")
    parser.add_argument("-o", "--output", default="libc_patched.so", help="Output path for patched libc.so")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[-] File not found: {args.input}")
        sys.exit(1)

    patcher = BionicPatcher(args.input)
    patcher.patch(args.output)


if __name__ == '__main__':
    main()
