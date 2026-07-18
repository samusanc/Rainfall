# level0 — read the logic, pass the argument

**Teaches:** reading disassembly; SUID privilege inheritance. No memory corruption.

## 1. What the binary does
Takes one argument. With the wrong value it prints `No !`. With the right value
it spawns a shell.
```
level0@RainFall:~$ ./level0        # segfault (no argv[1] to read)
level0@RainFall:~$ ./level0 a      # No !
```

## 2. Reconstructed C
```c
int main(int ac, char **av) {
    if (atoi(av[1]) != 423)
        fwrite("No !\n", 1, 5, stderr);
    else {
        char *args[] = { strdup("/bin/sh"), NULL };
        setresgid(getegid(), getegid(), getegid());   // drop to the SUID gid
        setresuid(geteuid(), geteuid(), geteuid());   // keep level1's euid
        execv("/bin/sh", args);
    }
    return 0;
}
```

## 3. The vulnerability
There is no memory bug — it is a **logic gate**. The disassembly shows:
```
call   atoi
cmp    eax,0x1a7          ; 0x1a7 = 423 in decimal
jne    main+152           ; not equal -> print "No !"
```
The binary is SUID `level1`, and it calls `setresuid(geteuid()...)` before
`execv`, so the `/bin/sh` it launches runs **as level1**.

## 4. Step by step
1. `info functions` → only `main`.
2. `disassemble main` → spot `cmp eax,0x1a7` right after `atoi`.
3. Convert `0x1a7` → 423 (that's what `atoi(argv[1])` must return).

## 5. Exploit
```
level0@RainFall:~$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
**Why it works:** you satisfied the check, so the else-branch runs and hands you
a shell carrying level1's privileges — enough to read level1's `.pass`.
