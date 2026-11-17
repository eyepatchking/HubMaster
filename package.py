"""Build self-contained HubMaster Windows x64 setup executables."""

import hashlib
import ctypes
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import time
import zipfile


def build(role, path, env):
    subprocess.run(
        ["go", "build", "-trimpath", "-buildvcs=false", "-ldflags",
         f"-H=windowsgui -X main.role={role}", "-o", str(path), "."],
        cwd=SOURCE, env=env, check=True,
    )
    add_icon(path)
    sign_binary(path)


def sign_binary(path):
    thumbprint = os.environ.get("HUBMASTER_SIGN_THUMBPRINT")
    if thumbprint:
        subprocess.run(["powershell.exe", "-NoProfile", "-File",
                        str(SOURCE / "sign-release.ps1"), "-Target", str(path),
                        "-Thumbprint", thumbprint], check=True)


def add_icon(path):
    data = (SOURCE / "hubmaster.ico").read_bytes()
    _, kind, count = struct.unpack_from("<HHH", data)
    if kind != 1 or not count:
        raise ValueError("Invalid icon")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.BeginUpdateResourceW.argtypes = [ctypes.c_wchar_p, ctypes.c_int]
    kernel.BeginUpdateResourceW.restype = ctypes.c_void_p
    kernel.UpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong]
    kernel.UpdateResourceW.restype = ctypes.c_int
    kernel.EndUpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_int]
    kernel.EndUpdateResourceW.restype = ctypes.c_int
    handle = kernel.BeginUpdateResourceW(str(path), False)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        group = bytearray(struct.pack("<HHH", 0, 1, count))
        for index in range(count):
            width, height, colors, reserved, planes, bits, size, offset = struct.unpack_from("<BBBBHHII", data, 6 + index * 16)
            image = data[offset:offset + size]
            buffer = ctypes.create_string_buffer(image)
            if not kernel.UpdateResourceW(handle, ctypes.c_void_p(3), ctypes.c_void_p(index + 1), 1033, buffer, size):
                raise ctypes.WinError(ctypes.get_last_error())
            group += struct.pack("<BBBBHHIH", width, height, colors, reserved, planes, bits, size, index + 1)
        buffer = ctypes.create_string_buffer(bytes(group))
        if not kernel.UpdateResourceW(handle, ctypes.c_void_p(14), ctypes.c_void_p(1), 1033, buffer, len(group)):
            raise ctypes.WinError(ctypes.get_last_error())
    except BaseException:
        kernel.EndUpdateResourceW(handle, True)
        raise
    if not kernel.EndUpdateResourceW(handle, False):
        raise ctypes.WinError(ctypes.get_last_error())


def tarball(files):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        for name, content, mode in files:
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            entry.mode = mode
            entry.mtime = int(time.time())
            entry.uname = entry.gname = "root"
            archive.addfile(entry, io.BytesIO(content))
    return result.getvalue()


def debian(build_dir, output_dir, env):
    binary = build_dir / "hubmaster-agent-linux"
    linux = env.copy()
    linux.update(GOOS="linux", GOARCH="amd64")
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "",
                    "-o", str(binary), "."], cwd=SOURCE, env=linux, check=True)
    control = b"""Package: hubmaster-agent
Version: 2.3.0
Section: admin
Priority: optional
Architecture: amd64
Maintainer: HubMaster
Depends: systemd, auditd
Description: HubMaster USB device management agent
 Local network agent for the HubMaster administrator console.
"""
    postinst = b"""#!/bin/sh
set -e
if [ "$1" = configure ] && [ -d /run/systemd/system ]; then
 systemctl daemon-reload
 systemctl enable hubmaster-agent.service
 systemctl restart hubmaster-agent.service
fi
exit 0
"""
    prerm = b"""#!/bin/sh
set -e
if [ "$1" = remove ] && [ -f /var/lib/hubmaster-agent/enrolled.json ] && [ ! -f /var/lib/hubmaster-agent/removed.json ]; then
 echo 'Authorize agent removal in HubMaster Admin first.' >&2
 exit 1
fi
if [ -d /run/systemd/system ]; then
 systemctl stop hubmaster-agent.service
 if [ "$1" = remove ]; then systemctl disable hubmaster-agent.service; fi
fi
exit 0
"""
    postrm = b"""#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
exit 0
"""
    service = b"""[Unit]
Description=HubMaster USB management agent
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/bin/hubmaster-agent --service
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
    desktop = b"""[Desktop Entry]
Type=Application
Name=HubMaster Agent
Comment=Show the pairing code
Exec=hubmaster-agent --otp
Icon=hubmaster-agent
Terminal=true
Categories=System;
"""
    ctl = tarball([("./control", control, 0o644), ("./postinst", postinst, 0o755),
                   ("./prerm", prerm, 0o755), ("./postrm", postrm, 0o755)])
    data = tarball([("./usr/bin/hubmaster-agent", binary.read_bytes(), 0o755),
                    ("./lib/systemd/system/hubmaster-agent.service", service, 0o644),
                    ("./usr/share/applications/hubmaster-agent.desktop", desktop, 0o644),
                    ("./usr/share/icons/hicolor/256x256/apps/hubmaster-agent.png",
                     (SOURCE / "web/logo.png").read_bytes(), 0o644)])
    def member(name, content):
        header = f"{name + '/':<16}{int(time.time()):<12}{0:<6}{0:<6}{'100644':<8}{len(content):<10}`\n".encode("ascii")
        return header + content + (b"\n" if len(content) % 2 else b"")
    output = output_dir / "hubmaster-agent_2.3.0_amd64.deb"
    output.write_bytes(b"!<arch>\n" + member("debian-binary", b"2.0\n") +
                       member("control.tar.gz", ctl) + member("data.tar.gz", data))
    print(f"{output.name}  {output.stat().st_size:,} bytes")


def installer(component, files, build_dir, output_dir, env):
    stub = build_dir / f"Setup-{component}.exe"
    build("Setup-" + component, stub, env)
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name in files:
            archive.write(build_dir / (name + ".exe"), name + ".exe")
    zipped = payload.getvalue()
    staging = build_dir / f"HubMaster-{component}-Setup.exe"
    with stub.open("rb") as source, staging.open("wb") as target:
        shutil.copyfileobj(source, target)
        target.write(zipped)
        target.write(b"HUBMZIP2")
        target.write(struct.pack("<Q", len(zipped)))
    with staging.open("rb") as check:
        check.seek(-16, os.SEEK_END)
        magic, length = struct.unpack("<8sQ", check.read(16))
        assert magic == b"HUBMZIP2" and length == len(zipped)
        check.seek(-16 - length, os.SEEK_END)
        with zipfile.ZipFile(io.BytesIO(check.read(length))) as archive:
            assert archive.testzip() is None
            assert archive.namelist() == [name + ".exe" for name in files]
            for name in files:
                assert archive.read(name + ".exe") == (build_dir / (name + ".exe")).read_bytes()
    final = output_dir / staging.name
    shutil.copyfile(staging, final)
    sign_binary(final)
    print(f"{final.name}  {final.stat().st_size:,} bytes  SHA256 {hashlib.sha256(final.read_bytes()).hexdigest()}")


SOURCE = Path(__file__).resolve().parent


def main():
    work = SOURCE.parent
    build_dir = work / "release"
    output_dir = work.parent / "outputs"
    build_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)
    env = os.environ.copy()
    env.update(GOCACHE=str(work / "gocache"), GOOS="windows", GOARCH="amd64", CGO_ENABLED="0")
    for role in ["Agent", "Admin"]:
        build(role, build_dir / (role + ".exe"), env)
    installer("Admin", ["Agent", "Admin"], build_dir, output_dir, env)
    installer("Agent", ["Agent"], build_dir, output_dir, env)
    debian(build_dir, output_dir, env)


if __name__ == "__main__":
    main()
