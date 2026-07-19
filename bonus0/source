#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *PROMPT = "(prompt)"; 

void p(char *dest, const char *prompt) {
    char input_buf[4104];
    char *newline;

    puts(prompt);

    int bytes_read = read(0, input_buf, 0x1000);
    if (bytes_read <= 0) return;

    newline = strchr(input_buf, '\n');
    if (newline != NULL) {
        *newline = '\0';
    }

    strncpy(dest, input_buf, 20);
}

void pp(char *output) {
    char first_word[20];
    char second_word[20];

    p(first_word, PROMPT);
    p(second_word, PROMPT);

    strcpy(output, first_word);

    int len = strlen(output);

    output[len] = ' ';
    output[len + 1] = '\0';

    strcat(output, second_word);
}

int main(void) {
    char final_buffer[54];

    pp(final_buffer);
    puts(final_buffer);

    return 0;
}
