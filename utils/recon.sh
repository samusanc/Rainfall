#!/bin/bash
# =============================================================================
#  recon.sh -- collect the static facts about a level binary.
#  DISPLAY ONLY: it runs the same commands you would type by hand. It does not
#  solve anything, so it is an allowed workflow helper (be ready to explain it).
#
#  Usage:  bash recon.sh ./level1
# =============================================================================

BIN="$1"
if [ -z "$BIN" ]; then
    echo "usage: bash recon.sh ./binary"
    exit 1
fi

echo "===== file (32-bit? stripped? dynamic?) ====="
file "$BIN"

echo
echo "===== permissions (is the SUID bit set, and whose?) ====="
ls -l "$BIN"

echo
echo "===== interesting strings (/bin/sh, format strings, messages) ====="
strings "$BIN" | grep -Ei 'bin/sh|/bin|%[0-9\$]*[nxsp]|flag|pass|wait|good|no !'

echo
echo "===== functions + main disassembly (gdb in batch mode) ====="
# gdb -batch runs the -ex commands non-interactively and prints the output.
gdb -batch \
    -ex 'set disassembly-flavor intel' \
    -ex 'info functions' \
    -ex 'disassemble main' \
    "$BIN"
