# 01 — The Workflow (same 4 phases every level)

Do these in order every time. Only Phase 4 changes shape from level to level.

## Phase 1 — Recon (in the shell, before gdb)

Answer: *what does it read, what does it print, does it crash, who do I become?*

```
ls -l ./levelX          # SUID bit + owner: -rwsr-s---+ 1 levelY  -> you become levelY
file ./levelX           # 32-bit, dynamically linked, not stripped
./levelX ; echo $?      # behavior with no args
./levelX AAAA           # behavior with an arg
strings ./levelX        # /bin/sh? messages? format strings?
```

Shortcut: `bash ../tools/recon.sh ./levelX` does all of this at once.

**Why:** SUID + owned by the next user is *the whole point* — when you run the
binary it executes with that user's privileges, so a shell it spawns can read
their `.pass`.

## Phase 2 — Static analysis (gdb, not running yet)

Answer: *what functions exist and what is the flow?*

```
gdb -x ../tools/.gdbinit ./levelX
(gdb) info functions       # or the `recon` macro: the MAP
(gdb) disassemble main
(gdb) disassemble <other>  # run, p, n, o, v, m, greetuser, setAnnotation...
```

Look for:
- an interesting function **never called** from main (level1 `run`, level5 `o`, level6 `n`, level7 `m`),
- a **dangerous call**: `gets`, `strcpy`, `strcat`, `memcpy`, `printf(user)`, `system`, `strdup`, `malloc`,
- a **comparison / check** that gates the win (`cmp eax,0x1a7`, `m == 64`, the `0xb0000000` filter).

## Phase 3 — Dynamic analysis (gdb, running) — find the two numbers

Every exploit needs **(a) the offset** and **(b) the target address**.

Find the offset:
```
(gdb) run < <(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5..."')    # stdin levels
(gdb) run $(python -c 'print "Aa0Aa1..."')                   # argv levels
Program received signal SIGSEGV ...
(gdb) info registers eip        # or eax for level9 — read the 4 crash bytes
(gdb) stack                     # the .gdbinit macro: registers + stack dump
```
Take the 4 bytes shown, look them up in the pattern → **offset**.

Find the target address:
```
(gdb) info functions run        # a function to jump to
objdump -R ./levelX | grep exit # a GOT slot to overwrite
ltrace ./levelX ...             # see malloc/strcpy addresses at runtime (heap levels)
```

## Phase 4 — Build and fire (your reasoning; per level)

Pick the technique from what Phases 2–3 revealed, then hand-build the payload.
Common delivery patterns:

```
# stdin, then keep the shell open ('-' feeds your keyboard after the payload):
cat /tmp/exploit - | ./levelX

# argv:
./levelX $(cat /tmp/exploit)
./levelX "$(python -c 'print ...')"

# two argv args (level6/7, bonus1/2):
./levelX $(python -c 'print ...') $(python -c 'print ...')
```

Build payloads with `../tools/payload.py` for the overflow family, or by hand
for format-string / logic levels.

## The line you must not cross
Gathering info and *delivering a payload you designed* = allowed helper.
A script that *finds the offset or emits the exploit for you* = forbidden. If
you cannot re-derive the offset and address by hand at the whiteboard, you
leaned on tooling too hard.
