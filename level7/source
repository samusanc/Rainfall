#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[80];

struct Node {
    int id;
    char *buf;
};

void m(void) {
    time_t tVar1 = time(NULL);
    printf("%s - %ld\n", c, tVar1);
}

int main(int argc, char *argv[]) {
    struct Node *node1;
    struct Node *node2;
    FILE *stream;

    node1 = (struct Node *)malloc(sizeof(struct Node));
    node1->id = 1;
    node1->buf = (char *)malloc(8);

    node2 = (struct Node *)malloc(sizeof(struct Node));
    node2->id = 2;
    node2->buf = (char *)malloc(8);

    if (argc > 2) {
        strcpy(node1->buf, argv[1]);
        strcpy(node2->buf, argv[2]);
    }

    stream = fopen("/home/user/level8/.pass", "r");
    if (stream != NULL) {
        fgets(c, 0x44, stream);
        fclose(stream);
    }

    puts("~~");
    return 0;
}
