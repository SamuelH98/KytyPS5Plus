#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
# SPDX-License-Identifier: GPL-2.0-or-later
"""Builds synthetic packages and checks pkg_extractor's CLI contract against them.

The synthetic layout follows the header offsets the extractor reads (FIH + CNT, big-endian CNT
fields, 32-byte entry records). These tests prove the extractor is self-consistent and safe on
hostile input; they cannot prove it matches a real console package.

usage: run_tests.py <path-to-pkg_extractor>
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

FLAG_FIRST_PATCH = 0x100000
FLAG_GD_AC = 0x2000000
ENC = 0x80000000


def psf(pairs):
    keys, data, entries = b"", b"", []
    for k, v in pairs:
        kb = k.encode() + b"\0"
        vb = v.encode() + b"\0"
        entries.append((len(keys), len(vb), len(data)))
        keys += kb
        data += vb
    key_off = 0x14 + 0x10 * len(pairs)
    data_off = key_off + len(keys)
    out = b"\0PSF" + struct.pack("<IIII", 0x101, key_off, data_off, len(pairs))
    for ko, ln, do in entries:
        out += struct.pack("<H", ko) + struct.pack(">H", 0x0204) + struct.pack("<III", ln, ln, do)
    return out + keys + data


def build_cnt(content_id, flags, entries):
    """entries: list of (id, name|None, data, flags1). Returns the CNT blob (header at 0)."""
    names = b"\0"
    name_off = {}
    for eid, name, _, _ in entries:
        if name:
            name_off[eid] = len(names)
            names += name.encode() + b"\0"
    all_entries = [(0x200, None, names, 0)] + list(entries)
    table_off = 0x800
    data_pos = table_off + 32 * len(all_entries)
    records, blobs = b"", b""
    for eid, _, data, f1 in all_entries:
        pad = (-len(blobs)) % 16
        blobs += b"\0" * pad
        off = data_pos + len(blobs)
        records += struct.pack(">6I", eid, name_off.get(eid, 0), f1, 0, off, len(data)) + b"\0" * 8
        blobs += data
    header = bytearray(0x800)
    header[0:4] = b"\x7fCNT"
    struct.pack_into(">I", header, 0x10, len(all_entries))
    struct.pack_into(">H", header, 0x14, len(all_entries))
    struct.pack_into(">H", header, 0x16, len(all_entries))
    struct.pack_into(">I", header, 0x18, table_off)
    header[0x40:0x40 + 36] = content_id.encode().ljust(36, b"\0")
    struct.pack_into(">I", header, 0x78, flags)
    return bytes(header) + records + blobs


def wrap_fih(cnt, signed=0x00, pfs_size=0x4000):
    cnt_base = 0x1000
    pfs_off = cnt_base + len(cnt)
    head = bytearray(cnt_base)
    head[0:4] = b"\x7fFIH"
    head[5] = signed
    struct.pack_into("<H", head, 6, 1)
    struct.pack_into("<Q", head, 0x10, pfs_off)
    struct.pack_into("<Q", head, 0x18, pfs_size)
    struct.pack_into("<Q", head, 0x58, cnt_base)
    return bytes(head) + cnt + b"\xAA" * pfs_size


TITLE = "PPSA01234"
CID = f"UP0000-{TITLE}_00-TESTLABEL0000000"


def param_json(title=TITLE, cid=CID):
    return json.dumps({"titleId": title, "contentId": cid, "contentVersion": "01.000.000"}).encode()


def base_entries():
    return [(0x2000, None, param_json(), 0), (0x1200, None, b"\x89PNG-fake-icon", 0)]


class Runner:
    def __init__(self, exe):
        self.exe = exe
        self.tmp = tempfile.TemporaryDirectory()
        self.failures = 0

    def path(self, *p):
        return os.path.join(self.tmp.name, *p)

    def write(self, name, data):
        with open(self.path(name), "wb") as f:
            f.write(data)
        return self.path(name)

    def run(self, *args):
        p = subprocess.run([self.exe, *args], capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout + p.stderr

    def check(self, name, cond, detail=""):
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else f"  -> {detail}"))
        if not cond:
            self.failures += 1


def main():
    exe = os.path.abspath(sys.argv[1])
    r = Runner(exe)

    # 1. bare CNT base game
    pkg = r.write("base.pkg", build_cnt(CID, 0, base_entries()))
    code, out = r.run(pkg, "--check-type")
    r.check("base --check-type -> 101", code == 101, (code, out))
    code, out = r.run(pkg, r.path("out1"))
    r.check("base extract exit 0", code == 0, (code, out))
    r.check("base param.json extracted", os.path.isfile(r.path("out1", TITLE, "sce_sys", "param.json")))
    r.check("base icon extracted with content",
            open(r.path("out1", TITLE, "sce_sys", "icon0.png"), "rb").read() == b"\x89PNG-fake-icon"
            if os.path.isfile(r.path("out1", TITLE, "sce_sys", "icon0.png")) else False)

    # 2. update
    pkg = r.write("patch.pkg", build_cnt(CID, FLAG_FIRST_PATCH, base_entries()))
    code, out = r.run(pkg, "--check-type")
    r.check("patch --check-type -> 102", code == 102, (code, out))
    code, out = r.run(pkg, r.path("out2"))
    r.check("patch goes to TITLE-patch", os.path.isdir(r.path("out2", TITLE + "-patch")), out)

    # 3. DLC via SFO category and via flag
    sfo = psf([("CATEGORY", "ac"), ("TITLE_ID", TITLE), ("CONTENT_ID", CID)])
    pkg = r.write("dlc.pkg", build_cnt(CID, 0, [(0x1000, None, sfo, 0)]))
    code, out = r.run(pkg, "--check-type")
    r.check("dlc (sfo category) -> 103", code == 103, (code, out))
    code, out = r.run(pkg, r.path("out3"))
    r.check("dlc goes to TITLE/label", os.path.isfile(r.path("out3", TITLE, "TESTLABEL0000000", "sce_sys", "param.sfo")), out)
    pkg = r.write("dlc2.pkg", build_cnt(CID, FLAG_GD_AC, base_entries()))
    code, _ = r.run(pkg, "--check-type")
    r.check("dlc (GD_AC flag) -> 103", code == 103, code)

    # 4. --type override
    pkg = r.write("base2.pkg", build_cnt(CID, 0, base_entries()))
    code, _ = r.run(pkg, "--check-type", "--type", "dlc")
    r.check("--type dlc override", code == 103, code)

    # 5. FIH debug package with inner PFS -> incomplete (exit 3), metadata still written
    pkg = r.write("debug.pkg", wrap_fih(build_cnt(CID, 0, base_entries())))
    code, out = r.run(pkg, "--check-type")
    r.check("fih debug --check-type -> 101", code == 101, (code, out))
    code, out = r.run(pkg, r.path("out5"))
    r.check("fih debug extract exit 3 (inner PFS not extracted)", code == 3, (code, out))
    r.check("fih debug says PFS not extracted", "NOT extracted" in out, out)
    r.check("fih debug metadata written", os.path.isfile(r.path("out5", TITLE, "sce_sys", "param.json")))

    # 6. default output next to the package
    code, _ = r.run(pkg)
    r.check("default output next to pkg", os.path.isdir(r.path(TITLE)))

    # 7. retail refused
    pkg = r.write("retail.pkg", wrap_fih(build_cnt(CID, 0, base_entries()), signed=0x80))
    code, out = r.run(pkg, "--check-type")
    r.check("retail --check-type -> 0", code == 0, (code, out))
    r.check("retail message explains why", "retail" in out.lower(), out)
    code, out = r.run(pkg, r.path("out7"))
    r.check("retail extract fails", code == 1 and not os.path.exists(r.path("out7")), (code, out))

    # 8. hostile names must not escape the output folder
    evil = [(0x2000, None, param_json(), 0), (0x9000, "../../escaped.txt", b"x", 0),
            (0x9001, "/abs/evil.txt", b"y", 0), (0x9002, "C:\\win\\evil.txt", b"z", 0)]
    pkg = r.write("evil.pkg", build_cnt(CID, 0, evil))
    code, out = r.run(pkg, r.path("out8", "nested"))
    r.check("traversal: nothing outside out dir",
            not os.path.exists(r.path("out8", "escaped.txt")) and not os.path.exists(r.path("escaped.txt"))
            and not os.path.exists("/abs/evil.txt"), out)
    r.check("traversal: entries kept under pkg_entries",
            os.path.isfile(r.path("out8", "nested", TITLE, "pkg_entries", "entry_0x9000.bin")), out)

    # 8b. title id / entitlement label come from the package too and must not escape either
    evil_title = [(0x2000, None, param_json(title="../../pwn_title"), 0)]
    pkg = r.write("evil_title.pkg", build_cnt(CID, 0, evil_title))
    code, out = r.run(pkg, r.path("out8b", "nested"))
    r.check("hostile titleId: falls back to content-id title, nothing escapes",
            os.path.isfile(r.path("out8b", "nested", TITLE, "sce_sys", "param.json"))
            and not os.path.exists(r.path("out8b", "pwn_title")) and not os.path.exists(r.path("pwn_title")), (code, out))
    evil_cid = f"UP0000-{TITLE}_00-../../pwn"
    pkg = r.write("evil_label.pkg", build_cnt(evil_cid, FLAG_GD_AC, base_entries()))
    code, out = r.run(pkg, r.path("out8c", "nested"))
    r.check("hostile entitlement label: stays inside title folder",
            os.path.isfile(r.path("out8c", "nested", TITLE, "sce_sys", "param.json"))
            and not os.path.exists(r.path("out8c", "pwn")) and not os.path.exists(r.path("out8c", "nested", "pwn")), (code, out))
    nothing = [(0x2000, None, b'{"titleId": "../x"}', 0)]
    pkg = r.write("no_title.pkg", build_cnt("", 0, nothing))
    code, out = r.run(pkg, "--check-type")
    r.check("no usable title id -> error", code == 0 and "title id" in out, (code, out))

    # 9. encrypted entry skipped, reported, exit 3
    pkg = r.write("enc.pkg", build_cnt(CID, 0, base_entries() + [(0x1200 + 1, None, b"secret", ENC)]))
    code, out = r.run(pkg, r.path("out9"))
    r.check("encrypted entry skipped (exit 3)", code == 3 and "encrypted" in out, (code, out))

    # 10. truncated / garbage / missing
    full = build_cnt(CID, 0, base_entries())
    pkg = r.write("trunc.pkg", full[:0x850])
    code, out = r.run(pkg, "--check-type")
    r.check("truncated package -> 0", code == 0, (code, out))
    pkg = r.write("garbage.pkg", b"not a package at all" * 100)
    code, out = r.run(pkg, "--check-type")
    r.check("garbage -> 0", code == 0 and "valid PKG" in out, (code, out))
    code, out = r.run(r.path("missing.pkg"), "--check-type")
    r.check("missing file -> 0", code == 0, (code, out))
    # entry whose data lies outside the file
    bad = bytearray(build_cnt(CID, 0, base_entries()))
    # entry 0 is the name table, entry 1 is param.json: give param.json an absurd size
    struct.pack_into(">I", bad, 0x800 + 32 + 20, 0x7FFFFFFF)
    pkg = r.write("oob.pkg", bytes(bad))
    code, out = r.run(pkg, r.path("out10"))
    r.check("out-of-bounds entry reported (exit 3)", code == 3 and "outside the file" in out, (code, out))
    r.check("out-of-bounds entry not written, others still are",
            not os.path.exists(r.path("out10", TITLE, "sce_sys", "param.json"))
            and os.path.isfile(r.path("out10", TITLE, "sce_sys", "icon0.png")), out)

    if r.failures:
        print(f"\n{r.failures} test(s) FAILED")
        return 1
    print("\nall tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
