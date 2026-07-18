# 00 — Memory Primer (read this first)

Everything in RainFall is 32-bit x86 (i386), little-endian. You must picture
memory to exploit it. This file is the mental model the whole guide builds on.

## 1. The process memory map

When the kernel runs an ELF binary, it lays memory out like this (low address at
the bottom, high at the top):

```
   HIGH ADDRESSES  0xffffffff
   +---------------------------+
   |   kernel space            |
   +---------------------------+
   |   stack   (grows DOWN ↓)  |   <- local variables, saved EIP/EBP, argv, env
   |            |              |
   |            v              |
   |                           |
   |            ^              |
   |            |              |
   |   heap    (grows UP ↑)    |   <- malloc()/strdup() live here (~0x0804a000)
   +---------------------------+
   |   .bss    (uninit globals)|   <- e.g. `int m = 0;`
   |   .data   (init globals)  |
   |   .got / .got.plt         |   <- table of resolved libc addresses (WRITABLE)
   |   .plt / .text  (code)    |   <- your functions, ~0x08048000
   +---------------------------+
   LOW ADDRESSES   0x08048000
```

Key numbers to recognise on sight in this VM:
- **`0x08048xxx`** → code (`.text`). Function addresses look like this.
- **`0x0804Axxx`** → heap (`malloc`/`strdup`).
- **`0x0804988x` / `0x08049xxx`** → globals and the GOT.
- **`0xbfffxxxx`** → the stack (locals, argv, env).

## 2. The stack and a function call (the cdecl convention)

On i386 arguments are pushed **right-to-left** onto the stack, then `call`
pushes the **return address**. Inside the function, the prologue saves the old
frame pointer:

```
push ebp          ; save caller's frame pointer
mov  ebp, esp     ; ebp = start of this frame
sub  esp, N       ; reserve N bytes for local variables
```

So a frame looks like this (this is THE picture for every buffer overflow):

```
        HIGH ADDRESSES
   +----------------------+
   |     arg2             |   ebp+0xc
   +----------------------+
   |     arg1             |   ebp+0x8
   +----------------------+
   |  saved return addr   |   ebp+0x4   <=== "EIP" we want to overwrite
   +----------------------+
   |  saved EBP (old)     |   ebp+0x0
   +----------------------+
   |                      |
   |   local buffer[]     |   ebp-0x?? ... grows toward the saved EIP
   |                      |
   +----------------------+   esp
        LOW ADDRESSES
```

**Why overflow works:** a buffer is *below* the saved return address in memory,
but writing into it moves *upward* (toward higher addresses). If you write more
bytes than the buffer holds, you keep going past `saved EBP` and overwrite the
`saved return address`. When the function runs `leave; ret`, the CPU pops that
value into `EIP` and jumps there — to wherever **you** chose.

```
   buffer[0] buffer[1] ... buffer[63] [saved EBP] [saved EIP]
   |<---------------- your input keeps writing this way ---------------->|
```

## 3. The offset

The **offset** is the exact number of bytes from the start of your input to the
4 bytes that land on the saved return address. You find it, you don't guess it:

1. Send a **De Bruijn pattern** `Aa0Aa1Aa2Aa3...` (every 4-byte window is unique).
2. The program crashes; `EIP` now holds 4 bytes of the pattern.
3. Look up those 4 bytes' position in the pattern → that's the offset.

Pattern + lookup tool: <https://wiremask.eu/tools/buffer-overflow-pattern-generator/>
(Generating/looking up a pattern is a helper, not an auto-solver — you still
build the payload yourself.)

## 4. Little-endian (why addresses look "backwards")

x86 stores the least-significant byte first. The function at `0x08048444` must be
written into memory as the bytes `44 84 04 08`:

```
python -c 'print "\x44\x84\x04\x08"'
```

`tools/payload.py` does this reversal for you with `struct.pack("<I", addr)`.

## 5. The heap and malloc

`malloc(n)` / `strdup(s)` return memory from the heap (~`0x0804a008` in these
binaries, and it is **stable** because ASLR is off). Two consecutive small
allocations sit next to each other with a small header/padding between them:

```
   0x0804a008  [ chunk A data ]
   0x0804a018  [ chunk B data ]   <- 16 bytes after A
```

That predictable adjacency is the whole idea behind level6/7/8: overflow one
heap chunk to reach a pointer stored in the next one.

## 6. PLT and GOT (needed for level5 and level7)

Libc functions are resolved lazily. A call to `puts` really does:

```
call puts@plt        ; in .plt
   -> jmp *0x8049928  ; the GOT entry: a POINTER to the real puts in libc
```

The **GOT** (Global Offset Table) is a writable table of these pointers. If you
overwrite the GOT entry for `exit` (level5) or `puts` (level7) with the address
of a function you like, the next call to that libc function jumps to *your*
target instead. Find GOT entries with:

```
objdump -R ./levelX          # lists relocation (GOT) entries
disassemble puts             # in gdb: shows  jmp *0xADDR  <- that ADDR is the GOT slot
```

## 7. Format strings (needed for level3/4/5)

`printf(buffer)` with **user-controlled** `buffer` is a bug. `printf` reads
format specifiers and pulls matching arguments *off the stack* — even if the
caller never pushed any. So:
- `%x` prints the next stack word as hex (used to *leak* / to *locate your own buffer*).
- `%N$x` prints the N-th stack word directly (positional).
- `%n` **writes** the number of bytes printed so far **into the address** given
  by the corresponding argument. Point that argument at a variable/GOT slot and
  you get an arbitrary write.
- `%<width>d` lets you inflate the printed byte count cheaply, so `%n` can write
  a large number (e.g. `%16930112d` before `%n`).

The recipe every format-string level uses:
1. Put the **target address** at the start of your buffer.
2. Add `%x %x %x ...` to find at which position your buffer bytes appear
   (you'll see `0x41414141` for `aaaa`). Say it's position 4.
3. Replace with `<addr> + padding + %4$n` so `%n` writes the byte count into
   your target address.
