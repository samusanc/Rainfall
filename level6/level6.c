#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void n(void) {
    system("/bin/cat /home/user/level7/.pass");
}

void m(void) {
    puts("Nope");
}

int main(int argc, char *argv[]) {
    char *dest;
    void (**fn_ptr)(void);

    dest = (char *)malloc(0x40);
    fn_ptr = (void (**)(void))malloc(sizeof(void *));
    *fn_ptr = m;

    if (argc > 1) {
        strcpy(dest, argv[1]);
    }
    (*fn_ptr)();
    return 0;
}
