# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>


void *ptr;
int size;



void menu() {
    puts("1. alloc <size>");
    puts("2. edit <data>");
    puts("3. show");
    puts("4. _free");
    puts("5. win");
    puts("6. exit");
}


void disable_buffering() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}


void alloc() {

    printf("size: ");
    scanf("%d", &size);

    if (size <= 0) {
        puts("invalid size");
        exit(1);
    }

    ptr = malloc(size);
    printf("allocated %d bytes\n", size);
}



void edit() {
    printf("data: ");
    read(0, ptr, size);

    puts("done");
}



void show() {
    if (ptr == NULL) {
        puts("no data");
        return;
    }

    printf("data: %s\n", ptr);
}


void _free() {
    if (ptr == NULL) {
        puts("no data");
        return;
    }

    free(ptr);
    puts("freed");
}


void win() {
    char *flag;
    for (int i = 0; i < 2; i++) {
        flag = malloc(0x180);
    }

    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        puts("flag not found");
        exit(1);
    }

    fgets(flag, 0x80, f);
    fclose(f);
}

void main() {

    disable_buffering();

    int choice = 0;

    while (1) {
        menu();

        printf("> ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                alloc();
                break;
            case 2:
                edit();
                break;
            case 3:
                show();
                break;
            case 4:
                _free(); 
                break;
            case 5: 
                win();
                break;
            case 6: return;
            default:
                puts("Invalid choice");
                exit(1);
        }

    }


}