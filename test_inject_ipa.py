# File: test_inject_ipa.py
# Comprehensive test suite for inject_ipa.py

import os
import sys
import struct
import tempfile
import zipfile
import plistlib
import unittest

from inject_ipa import (
    inject_macho,
    patch_ipa,
    MH_MAGIC_64,
    FAT_MAGIC,
    FAT_MAGIC_64,
    CPU_TYPE_ARM64,
    LC_SEGMENT_64,
    LC_LOAD_DYLIB
)

class TestMachOInjector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_synthetic_macho_64_bytes(self, pad_size: int = 1024, first_sect_gap: int = 1024) -> bytearray:
        ncmds = 1
        sizeofcmds = 72 + 80 # segment_64 + section_64
        header = struct.pack(
            "<IIIIIIII",
            MH_MAGIC_64,
            CPU_TYPE_ARM64,
            0,
            2, # MH_EXECUTE
            ncmds,
            sizeofcmds,
            0x00200085,
            0
        )
        
        seg_name = b"__TEXT" + b"\x00" * 10
        vmaddr = 0x100000000
        vmsize = 0x4000
        fileoff = 0
        filesize = 0x4000
        seg_cmd = struct.pack(
            "<II16sQQQQiiII",
            LC_SEGMENT_64,
            72 + 80,
            seg_name,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            7, 5, 1, 0
        )
        
        sect_name = b"__text" + b"\x00" * 10
        first_sect_offset = 32 + sizeofcmds + first_sect_gap
        sect = struct.pack(
            "<16s16sQQIIIIIIII",
            sect_name,
            seg_name,
            vmaddr + first_sect_offset,
            64,
            first_sect_offset,
            4,
            0, 0, 0, 0, 0, 0
        )
        
        padding = b"\x00" * (first_sect_gap + pad_size)
        code = b"\x1f\x20\x03\xd5" * 16
        return bytearray(header + seg_cmd + sect + padding + code)

    def test_thin_macho_injection(self):
        bin_path = os.path.join(self.temp_dir.name, "thin_binary")
        raw = self._create_synthetic_macho_64_bytes()
        with open(bin_path, "wb") as f:
            f.write(raw)

        dylib = "@executable_path/Frameworks/BumpSpoof.dylib"
        inject_macho(bin_path, dylib)

        with open(bin_path, "rb") as f:
            data = f.read()

        ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
        self.assertEqual(ncmds, 2)
        self.assertIn(dylib.encode("utf-8"), data)

        # Test idempotency (should not duplicate)
        inject_macho(bin_path, dylib)
        with open(bin_path, "rb") as f:
            data2 = f.read()
        ncmds2, sizeofcmds2 = struct.unpack_from("<II", data2, 16)
        self.assertEqual(ncmds2, 2)
        self.assertEqual(sizeofcmds2, sizeofcmds)

    def test_universal_fat_32_injection(self):
        bin_path = os.path.join(self.temp_dir.name, "fat32_binary")
        slice_bytes = self._create_synthetic_macho_64_bytes()
        slice_offset = 0x1000 # 4096 aligned
        slice_size = len(slice_bytes)

        # FAT header with 1 arch (arm64)
        fat_hdr = struct.pack(">II", FAT_MAGIC, 1)
        fat_arch = struct.pack(">IIIII", CPU_TYPE_ARM64, 0, slice_offset, slice_size, 12)

        total_header = fat_hdr + fat_arch
        pad = b"\x00" * (slice_offset - len(total_header))
        fat_binary = total_header + pad + slice_bytes

        with open(bin_path, "wb") as f:
            f.write(fat_binary)

        dylib = "@executable_path/Frameworks/BumpSpoof.dylib"
        inject_macho(bin_path, dylib)

        with open(bin_path, "rb") as f:
            data = f.read()

        ncmds, sizeofcmds = struct.unpack_from("<II", data, slice_offset + 16)
        self.assertEqual(ncmds, 2)
        self.assertIn(dylib.encode("utf-8"), data[slice_offset:])

    def test_full_ipa_patch_flow(self):
        # Create a synthetic .ipa (zip with Payload/App.app/...)
        ipa_in = os.path.join(self.temp_dir.name, "Test.ipa")
        ipa_out = os.path.join(self.temp_dir.name, "Test_Patched.ipa")
        dummy_dylib = os.path.join(self.temp_dir.name, "BumpSpoof.dylib")

        with open(dummy_dylib, "wb") as f:
            f.write(b"\xca\xfe\xba\xbe\x00\x00\x00\x00")

        app_name = "Bump.app"
        exec_name = "Bump"
        macho_bytes = self._create_synthetic_macho_64_bytes()

        info_plist = {
            "CFBundleExecutable": exec_name,
            "CFBundleIdentifier": "com.test.bump",
            "CFBundleVersion": "1.0",
        }
        plist_bytes = plistlib.dumps(info_plist)

        with zipfile.ZipFile(ipa_in, "w") as zf:
            zf.writestr(f"Payload/{app_name}/Info.plist", plist_bytes)
            zf.writestr(f"Payload/{app_name}/{exec_name}", macho_bytes)

        patch_ipa(ipa_in, dummy_dylib, ipa_out)
        self.assertTrue(os.path.isfile(ipa_out))

        # Inspect patched IPA
        with zipfile.ZipFile(ipa_out, "r") as zf:
            namelist = zf.namelist()
            self.assertIn(f"Payload/{app_name}/Frameworks/BumpSpoof.dylib", namelist)
            
            # Check plist document sharing flags
            plist_data = plistlib.loads(zf.read(f"Payload/{app_name}/Info.plist"))
            self.assertTrue(plist_data.get("UIFileSharingEnabled"))
            self.assertTrue(plist_data.get("LSSupportsOpeningDocumentsInPlace"))

            # Check Mach-O in zip
            patched_exec = zf.read(f"Payload/{app_name}/{exec_name}")
            self.assertIn(b"@executable_path/Frameworks/BumpSpoof.dylib", patched_exec)

            # Check permissions
            info = zf.getinfo(f"Payload/{app_name}/{exec_name}")
            mode = (info.external_attr >> 16) & 0o777
            self.assertEqual(mode & 0o111, 0o111) # executable bit preserved!

if __name__ == "__main__":
    unittest.main()
