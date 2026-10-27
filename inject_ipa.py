# File: inject_ipa.py
# Purpose: Robust Mach-O (thin 64-bit arm64 and FAT Universal) injector for iOS 15.0 - 26.5
# Injects LC_LOAD_DYLIB, preserves file permissions, and sets Info.plist document sharing.

import sys
import os
import struct
import shutil
import zipfile
import plistlib
import tempfile
import time
import subprocess

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

CPU_TYPE_ARM64 = 0x0100000C

LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
LC_REEXPORT_DYLIB = 0x1F | 0x80000000

def _find_earliest_section_offset(data: bytearray, slice_offset: int, ncmds: int, sizeofcmds: int) -> int:
    """Finds the lowest file offset of any section in LC_SEGMENT_64 to know safe header padding limit."""
    header_size = 32
    cmd_offset = slice_offset + header_size
    cmd_end_offset = cmd_offset + sizeofcmds
    earliest_offset = None

    cur = cmd_offset
    for _ in range(ncmds):
        if cur + 8 > cmd_end_offset:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, cur)
        if cmdsize < 8 or cur + cmdsize > len(data):
            break

        if cmd == LC_SEGMENT_64:
            if cmdsize >= 72:
                # LC_SEGMENT_64: cmd(4), cmdsize(4), segname(16), vmaddr(8), vmsize(8), fileoff(8), filesize(8), maxprot(4), initprot(4), nsects(4), flags(4)
                nsects = struct.unpack_from("<I", data, cur + 64)[0]
                sect_cur = cur + 72
                for _ in range(nsects):
                    if sect_cur + 80 > cur + cmdsize:
                        break
                    # section_64: sectname(16), segname(16), addr(8), size(8), offset(4)
                    sect_off = struct.unpack_from("<I", data, sect_cur + 48)[0]
                    sect_size = struct.unpack_from("<Q", data, sect_cur + 40)[0]
                    if sect_off > 0 and sect_size > 0:
                        relative_sect_off = slice_offset + sect_off
                        if earliest_offset is None or relative_sect_off < earliest_offset:
                            earliest_offset = relative_sect_off
                    sect_cur += 80

        cur += cmdsize

    return earliest_offset

def _inject_slice(data: bytearray, slice_offset: int, slice_size: int, dylib_install_path: str) -> bool:
    """Injects LC_LOAD_DYLIB into a single 64-bit Mach-O slice. Returns True if modified."""
    if slice_offset + 32 > len(data):
        raise ValueError(f"Slice offset {slice_offset} exceeds binary length {len(data)}")

    magic = struct.unpack_from("<I", data, slice_offset)[0]
    if magic != MH_MAGIC_64:
        raise ValueError(f"Slice at offset {slice_offset} is not 64-bit little-endian Mach-O (magic={hex(magic)})")

    ncmds, sizeofcmds = struct.unpack_from("<II", data, slice_offset + 16)
    header_size = 32
    cmd_offset = slice_offset + header_size
    cmd_end_offset = cmd_offset + sizeofcmds

    # Check if dylib already loaded and track LC_CODE_SIGNATURE
    path_bytes = dylib_install_path.encode("utf-8") + b"\x00"
    code_sig_offset = None
    code_sig_cmdsize = 16

    cur = cmd_offset
    for _ in range(ncmds):
        if cur + 8 > cmd_end_offset:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, cur)
        if cmdsize < 8 or cur + cmdsize > len(data):
            break
        if cmd == 0x1D:  # LC_CODE_SIGNATURE
            code_sig_offset = cur
            code_sig_cmdsize = cmdsize
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            # dylib_command: cmd(4), cmdsize(4), name_offset(4), timestamp(4), current_version(4), compatibility_version(4)
            if cmdsize >= 24:
                name_offset = struct.unpack_from("<I", data, cur + 8)[0]
                if name_offset < cmdsize:
                    loaded_path = bytes(data[cur + name_offset : cur + cmdsize]).split(b"\x00")[0]
                    if loaded_path == dylib_install_path.encode("utf-8"):
                        print(f"[*] {dylib_install_path} already linked in slice at 0x{slice_offset:x}.")
                        return False
        cur += cmdsize

    base_struct_size = 24
    total_len = base_struct_size + len(path_bytes)
    cmdsize = (total_len + 7) & ~7
    padding_len = cmdsize - total_len

    # Safety check: available space before first section
    earliest_sect = _find_earliest_section_offset(data, slice_offset, ncmds, sizeofcmds)
    if earliest_sect is not None:
        if cmd_end_offset + cmdsize > earliest_sect:
            raise RuntimeError(
                f"Insufficient Mach-O header padding: end of commands 0x{cmd_end_offset + cmdsize:x} "
                f"exceeds first section offset 0x{earliest_sect:x}"
            )
    else:
        # Fallback slack check
        slack = data[cmd_end_offset : cmd_end_offset + cmdsize]
        if any(b != 0 for b in slack):
            raise RuntimeError(f"Insufficient Mach-O header slack space at 0x{cmd_end_offset:x}.")

    dylib_cmd = struct.pack(
        "<IIIIII",
        LC_LOAD_DYLIB,
        cmdsize,
        24,          # name offset (points immediately after struct)
        2,           # timestamp
        0x010000,    # current_version 1.0.0
        0x010000     # compatibility_version 1.0.0
    ) + path_bytes + (b"\x00" * padding_len)

    # In Mach-O, LC_CODE_SIGNATURE MUST remain the very last load command.
    if code_sig_offset is not None and code_sig_offset + code_sig_cmdsize == cmd_end_offset:
        sig_data = bytes(data[code_sig_offset : cmd_end_offset])
        data[code_sig_offset : code_sig_offset + cmdsize] = dylib_cmd
        data[code_sig_offset + cmdsize : code_sig_offset + cmdsize + code_sig_cmdsize] = sig_data
    else:
        data[cmd_end_offset : cmd_end_offset + cmdsize] = dylib_cmd

    struct.pack_into("<II", data, slice_offset + 16, ncmds + 1, sizeofcmds + cmdsize)
    print(f"[+] Injected {dylib_install_path} into slice at 0x{slice_offset:x} (new ncmds={ncmds+1}, LC_CODE_SIGNATURE preserved at end)")
    return True

def inject_macho(binary_path: str, dylib_install_path: str) -> None:
    """Supports both thin 64-bit arm64 Mach-O and FAT Universal binaries."""
    with open(binary_path, "r+b") as f:
        data = bytearray(f.read())
        if len(data) < 32:
            raise ValueError(f"File too small to be Mach-O: {binary_path}")

        magic_be = struct.unpack_from(">I", data, 0)[0]
        magic_le = struct.unpack_from("<I", data, 0)[0]

        modified = False
        if magic_le == MH_MAGIC_64:
            modified = _inject_slice(data, 0, len(data), dylib_install_path)
        elif magic_be in (FAT_MAGIC, FAT_CIGAM):
            # 32-bit FAT binary header
            nfat_arch = struct.unpack_from(">I", data, 4)[0]
            print(f"[*] Detected Universal FAT binary with {nfat_arch} architectures.")
            injected_slices = 0
            for i in range(nfat_arch):
                arch_off = 8 + (i * 20)
                cputype, cpusubtype, offset, size, align = struct.unpack_from(">IIIII", data, arch_off)
                if cputype == CPU_TYPE_ARM64:
                    print(f"[*] Processing arm64 slice at 0x{offset:x} (size={size}).")
                    if _inject_slice(data, offset, size, dylib_install_path):
                        modified = True
                    injected_slices += 1
            if injected_slices == 0:
                raise ValueError("No arm64 slice found in Universal FAT binary.")
        elif magic_be in (FAT_MAGIC_64, FAT_CIGAM_64):
            # 64-bit FAT binary header
            nfat_arch = struct.unpack_from(">I", data, 4)[0]
            print(f"[*] Detected 64-bit Universal FAT binary with {nfat_arch} architectures.")
            injected_slices = 0
            for i in range(nfat_arch):
                arch_off = 8 + (i * 32)
                cputype, cpusubtype, offset, size, align, reserved = struct.unpack_from(">IIQQII", data, arch_off)
                if cputype == CPU_TYPE_ARM64:
                    print(f"[*] Processing arm64 slice at 0x{offset:x} (size={size}).")
                    if _inject_slice(data, offset, size, dylib_install_path):
                        modified = True
                    injected_slices += 1
            if injected_slices == 0:
                raise ValueError("No arm64 slice found in 64-bit Universal FAT binary.")
        else:
            raise ValueError(f"Unsupported Mach-O magic: 0x{magic_le:08x} / 0x{magic_be:08x}")

        if modified:
            f.seek(0)
            f.write(data)
            f.flush()
            print(f"[+] Mach-O modifications saved to {binary_path}")

def patch_ipa(in_ipa: str, dylib_path: str, out_ipa: str) -> None:
    """Unpacks IPA, copies dylib to Frameworks, injects LC_LOAD_DYLIB, sets document sharing, and repacks."""
    if not os.path.isfile(in_ipa):
        raise FileNotFoundError(f"Input IPA not found: {in_ipa}")
    if not os.path.isfile(dylib_path):
        raise FileNotFoundError(f"Dylib to inject not found: {dylib_path}")

    with tempfile.TemporaryDirectory() as workdir:
        print(f"[*] Extracting {in_ipa}...")
        with zipfile.ZipFile(in_ipa, "r") as zf:
            zf.extractall(workdir)

        payload_dir = os.path.join(workdir, "Payload")
        if not os.path.isdir(payload_dir):
            raise FileNotFoundError("Invalid IPA: Missing 'Payload/' directory.")

        apps = [d for d in os.listdir(payload_dir) if d.endswith(".app")]
        if not apps:
            raise FileNotFoundError("No .app bundle found inside Payload/")
        app_dir = os.path.join(payload_dir, apps[0])

        # 1. Strip FairPlay DRM directories (SC_Info) across the entire package
        for root, dirs, _ in os.walk(workdir):
            for d in list(dirs):
                if d == "SC_Info":
                    sc_path = os.path.join(root, d)
                    print(f"[*] Removing FairPlay DRM directory: {sc_path}")
                    shutil.rmtree(sc_path, ignore_errors=True)
                    dirs.remove(d)

        # 2. Strip stale App Store code signatures so Sideloadly/AltStore can cleanly sign
        for root, dirs, _ in os.walk(workdir):
            for d in list(dirs):
                if d == "_CodeSignature":
                    cs_path = os.path.join(root, d)
                    print(f"[*] Removing stale code signature: {cs_path}")
                    shutil.rmtree(cs_path, ignore_errors=True)
                    dirs.remove(d)

        # 3. Strip App Extensions (PlugIns) which trigger fatal amfid entitlement crashes on personal Apple IDs
        plugins_dir = os.path.join(app_dir, "PlugIns")
        if os.path.isdir(plugins_dir):
            print(f"[*] Stripping App Extensions directory: {plugins_dir}")
            shutil.rmtree(plugins_dir, ignore_errors=True)

        watch_dir = os.path.join(app_dir, "Watch")
        if os.path.isdir(watch_dir):
            shutil.rmtree(watch_dir, ignore_errors=True)

        info_plist_path = os.path.join(app_dir, "Info.plist")
        if not os.path.isfile(info_plist_path):
            raise FileNotFoundError(f"Missing Info.plist inside {app_dir}")

        with open(info_plist_path, "rb") as pf:
            plist_data = plistlib.load(pf)

        # Enable iTunes / Files app document sharing to load route.gpx
        plist_data["UIFileSharingEnabled"] = True
        plist_data["LSSupportsOpeningDocumentsInPlace"] = True
        with open(info_plist_path, "wb") as pf:
            plistlib.dump(plist_data, pf)
        print("[+] Enabled UIFileSharingEnabled and LSSupportsOpeningDocumentsInPlace in Info.plist")

        exec_name = plist_data.get("CFBundleExecutable")
        if not exec_name:
            raise KeyError("CFBundleExecutable key missing from Info.plist")
        exec_path = os.path.join(app_dir, exec_name)
        if not os.path.isfile(exec_path):
            raise FileNotFoundError(f"App executable does not exist: {exec_path}")

        frameworks_dir = os.path.join(app_dir, "Frameworks")
        os.makedirs(frameworks_dir, exist_ok=True)
        dylib_name = os.path.basename(dylib_path)
        dest_dylib = os.path.join(frameworks_dir, dylib_name)
        shutil.copy2(dylib_path, dest_dylib)
        print(f"[+] Placed {dylib_name} in {frameworks_dir}")

        inject_macho(exec_path, f"@executable_path/Frameworks/{dylib_name}")

        # On macOS, re-sign frameworks and main app bundle so code signatures are 100% valid
        if sys.platform == "darwin":
            try:
                for root, _, files in os.walk(frameworks_dir):
                    for f in files:
                        if f.endswith(".dylib") or f.endswith(".framework"):
                            subprocess.run(["codesign", "-f", "-s", "-", os.path.join(root, f)], check=False)
                subprocess.run(["codesign", "-f", "-s", "-", app_dir], check=False)
                print("[+] Ad-hoc resigned app bundle and frameworks on macOS.")
            except Exception as e:
                print(f"[!] Warning during codesign: {e}")

        print(f"[*] Repackaging output IPA with preserved POSIX permissions: {out_ipa}")
        with zipfile.ZipFile(out_ipa, "w", compression=zipfile.ZIP_DEFLATED) as out_zf:
            for root, _, files in os.walk(workdir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, workdir).replace("\\", "/")
                    
                    st = os.stat(full_path)
                    zinfo = zipfile.ZipInfo(rel_path)
                    zinfo.date_time = time.localtime(st.st_mtime)[:6]
                    zinfo.compress_type = zipfile.ZIP_DEFLATED
                    # Preserve executable permissions (0o755 vs 0o644)
                    mode = st.st_mode
                    if file == exec_name or file.endswith(".dylib"):
                        mode |= 0o755
                    zinfo.external_attr = (mode & 0xFFFF) << 16

                    with open(full_path, "rb") as src_f:
                        out_zf.writestr(zinfo, src_f.read())

        print(f"[+] Repackaged iOS 26.5-ready IPA: {out_ipa}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <Input.ipa> <BumpSpoof.dylib> <Output.ipa>")
        sys.exit(1)
    patch_ipa(sys.argv[1], sys.argv[2], sys.argv[3])
