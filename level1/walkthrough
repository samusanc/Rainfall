# level1

First, we decompile the code into C.

We notice that we can trigger a segmentation fault by supplying 76 characters of input. We also see that the program has a helper function named `run` that executes a shell, but it is not called by `main`.

Therefore, we can use a stack-based buffer overflow to redirect execution and run that function.

To do this, we need to know the target address of `run` and the offset. The offset in this case is exactly 76 bytes.

First, we get the address of the `run` function by running the program in GDB and using `info functions`:
```text
0x08048444
```

Using Python, we can generate our exploit payload. We use the `[::-1]` slice to reverse the target address bytes to account for little-endian endianness:
```bash
python -c 'print "a" * 76 + "\x08\x04\x84\x44"[::-1]' > payload
```

Then we execute the payload using pipes to exploit the binary:
```bash
(cat payload; cat) | ./level1
```

### Why we can overwrite the address
To understand why this works, we need to look at how the return instruction (`ret`) behaves. When a function returns, the program pops the saved return address from the stack into the instruction pointer (EIP) to resume execution. In this case, the buffer boundary aligns perfectly with the saved return address (EIP) offset. While the offset matches the buffer size here, we should always verify the stack layout and calculate the exact offset by checking how the base pointer (EBP) is set up.
