# RainFall — Study Guide

A step-by-step guide to every level. Read the two foundation files first, then
each level in order. Every level file has the same sections so you always know
where to look:

1. **What the binary does** (observed behavior)
2. **Reconstructed C** (what the source looks like)
3. **The vulnerability** (the bug and why it exists)
4. **Memory map** (stack/heap/GOT diagram for this level)
5. **Step-by-step** (exact recon → gdb → offset → payload, with *why* at each step)
6. **The exploit** (final payload and why it works)

> Everything here is for the sandbox VM where ASLR, NX, stack canaries and RELRO
> are **disabled**. That is why fixed addresses and stack shellcode work. On a
> modern system these same programs would be much harder to exploit — that is
> the lesson the project is teaching.

## Read first
- [`00-memory-primer.md`](00-memory-primer.md) — how process memory, the stack, the heap, calling conventions, and the GOT/PLT work. Referenced by every level.
- [`01-workflow.md`](01-workflow.md) — the repeatable 4-phase method (recon → static → dynamic → exploit) with the exact gdb and python commands.

## The levels, and the technique each one teaches

| Level | Bug / entry point | Technique | Fits `payload.py`? |
|-------|-------------------|-----------|--------------------|
| [level0](level0.md) | `atoi(argv[1]) == 423` | read the logic, pass the arg | — |
| [level1](level1.md) | `gets()` stack overflow | ret2func (jump to `run`) | ✅ |
| [level2](level2.md) | `gets()` + return-address filter | shellcode on the heap (via `strdup`) | ✅ |
| [level3](level3.md) | `printf(buffer)` | format string `%n` write to a global | ❌ |
| [level4](level4.md) | `printf(buffer)` | format string `%n` with width padding | ❌ |
| [level5](level5.md) | `printf(buffer)` | format string → overwrite `exit` GOT entry | ❌ |
| [level6](level6.md) | heap `strcpy` overflow | overwrite a heap function pointer | ✅ (argv) |
| [level7](level7.md) | heap `strcpy` overflow | overwrite `puts` GOT via a heap pointer | ✅ (argv) |
| [level8](level8.md) | logic / heap adjacency | craft `auth`/`service` state | — |
| [level9](level9.md) | C++ `memcpy` overflow | overwrite an object's function pointer, shellcode | ✅ (argv) |
| [bonus0](bonus0.md) | non-terminated `strncpy` | overflow + shellcode in a NOP sled | partly |
| [bonus1](bonus1.md) | signed `memcpy` length | integer overflow to bypass a size check | ✅ (argv) |
| [bonus2](bonus2.md) | `strcat` overflow | shellcode in an env var + return to NOP sled | partly |
| [bonus3](bonus3.md) | `atoi` index + `strcmp` | logic trick with an empty argument | — |

## The two hard rules from the subject
- **No binaries in the repo.** Ever.
- **No automation tool** (no auto-solver/ROP/brute-force). Helper scripts that
  *deliver* an exploit you designed are fine — see `../tools/`. You must be able
  to explain everything by hand at the defense.
