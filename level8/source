#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

struct auth_t {
    char name[32];
    int authenticated;
};

struct auth_t *auth = NULL;
char *service = NULL;

int main(void) {
    char input[128];

    while (true) {
        printf("%p, %p \n", (void *)auth, (void *)service);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            return 0;
        }

        if (strncmp(input, "auth ", 5) == 0) {
            auth = malloc(sizeof(struct auth_t));
            if (auth != NULL) {
                memset(auth, 0, sizeof(struct auth_t));
                
                if (strlen(input + 5) < 31) {
                    strcpy(auth->name, input + 5);
                }
            }
        }

        if (strncmp(input, "reset", 5) == 0) {
            free(auth);
        }

        if (strncmp(input, "service", 7) == 0) {
            service = strdup(input + 7);
        }

        if (strncmp(input, "login", 5) == 0) {
            if (auth != NULL && auth->authenticated != 0) {
                system("/bin/sh");
            } else {
                fwrite("Password:\n", 1, 10, stdout);
            }
        }
    }
    return 0;
}
