# File: make_host_ipa.py
# Purpose: Packages the compiled standalone host into BaseHost.ipa for injection

import os
import sys
import zipfile
import time

def build_base_host_ipa(exec_path: str, plist_path: str, out_ipa: str) -> None:
    if not os.path.isfile(exec_path):
        raise FileNotFoundError(f"Host binary not found: {exec_path}")
    if not os.path.isfile(plist_path):
        raise FileNotFoundError(f"Info.plist not found: {plist_path}")

    app_dir = "Payload/Bump.app"
    with zipfile.ZipFile(out_ipa, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Add Info.plist
        with open(plist_path, "rb") as pf:
            plist_bytes = pf.read()
        zinfo_plist = zipfile.ZipInfo(f"{app_dir}/Info.plist")
        zinfo_plist.date_time = time.localtime()[:6]
        zinfo_plist.external_attr = (0o644 & 0xFFFF) << 16
        zf.writestr(zinfo_plist, plist_bytes)

        # Add executable with 0o755 permissions
        with open(exec_path, "rb") as ef:
            exec_bytes = ef.read()
        zinfo_exec = zipfile.ZipInfo(f"{app_dir}/Bump")
        zinfo_exec.date_time = time.localtime()[:6]
        zinfo_exec.external_attr = (0o755 & 0xFFFF) << 16
        zf.writestr(zinfo_exec, exec_bytes)

    print(f"[+] Successfully generated standalone host IPA: {out_ipa}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <host_exec> <host_Info.plist> <out.ipa>")
        sys.exit(1)
    build_base_host_ipa(sys.argv[1], sys.argv[2], sys.argv[3])
