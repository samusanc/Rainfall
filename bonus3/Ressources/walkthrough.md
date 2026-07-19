# bonus3

### Decompilation

We analyze the binary in Ghidra. The `main` function opens the password file, reads its contents into local buffers, and compares the password against `argv[1]`:

```c
int main(int ac, char **av) {
    char buffer[132];
    FILE *f = fopen("/home/user/end/.pass", "r");
    
    memset(buffer, 0, 132);
    
    if (f == NULL || ac != 2) {
        return -1;
    }
    
    fread(buffer, 1, 66, f);
    buffer[65] = '\0';
    
    int index = atoi(av[1]);
    buffer[index] = '\0';
    
    fread(buffer + 66, 1, 65, f);
    fclose(f);
    
    if (strcmp(buffer, av[1]) == 0) {
        execl("/bin/sh", "sh", NULL);
    } else {
        puts(buffer + 66);
    }
    
    return 0;
}
```

The program opens `/home/user/end/.pass` and reads the first 66 bytes into the `buffer`. It then converts `argv[1]` to an integer using `atoi` and terminates the string by writing a null byte at that index:
```c
buffer[atoi(av[1])] = '\0';
```

Finally, it compares the modified buffer against `argv[1]`:
```c
if (strcmp(buffer, av[1]) == 0)
```
If both strings match, the program executes `execl("/bin/sh")` to spawn a shell.

### Bypassing the Password Check

To trigger the shell, `buffer` (the hidden password string) must match `argv[1]`. Normally, we do not know the contents of the password file.

However, `argv[1]` is used in two ways:
1. As the input passed to `strcmp`.
2. As the index parameter passed to `atoi` to truncate the buffer: `buffer[atoi(av[1])] = '\0'`.

This means that while we cannot control the original contents of the buffer, we can choose where to truncate it.

### Truncating to an Empty String

The easiest string to reproduce without knowing the password is the empty string (`""`).

To turn `buffer` into an empty string, we want the program to write a null byte at index `0`:
```c
buffer[0] = '\0';
```
This requires `atoi(argv[1])` to return `0`.

Passing `"0"` as `argv[1]` would satisfy `atoi("0") == 0` and truncate `buffer` to `""`, but the final comparison would fail:
`strcmp("", "0") != 0`

However, `atoi` also returns `0` when the input is not a valid number (e.g., an empty string `""`):
`atoi("") == 0`

By passing an empty string `""` as `argv[1]`:
1. `atoi("")` returns `0`.
2. `buffer[0]` is overwritten with `\0`, turning it into `""`.
3. The comparison becomes `strcmp("", "") == 0`.
The check succeeds and spawns the shell.

### Execution

We run the binary with an empty string as the only argument:
```bash
./bonus3 ""
```

This successfully executes the shell:
```bash
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```
Once you obtain the shell, reading `/home/user/end/end` prints:
`Congratulations graduate!` 🎓
