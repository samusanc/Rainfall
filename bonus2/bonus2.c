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
