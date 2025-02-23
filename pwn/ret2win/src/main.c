# include <stdio.h>
# include <stdlib.h>



void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void win() {
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("flag.txt not found\n");
        exit(1);
    }

    char flag[0x100];
    fgets(flag, 0x100, f);
    printf("yey: %s\n", flag);
}

void main() {
    init();
    char buffer[0x100];
    printf("show me what you've got> ");
    gets(buffer);
    printf("bailing out\n");
}