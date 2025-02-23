# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>




// array for allocations
char *allocs[10];
// array for sizes
int sizes[10];



void menu() {
    puts("1. avocado");
    puts("2. kiwi");
    puts("3. orange");
    puts("4. mango");
    puts("5. pineapple");
}


void disable_buffering() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}


void avocado() {
    int idx = 0;
    int size = 0;

    printf("index: ");
    scanf("%d", &idx);

    if (idx < 0 || idx >= 10) {
        puts("invalid index");
        exit(1);
    }

    printf("size: ");
    scanf("%d", &size);

    if (size <= 0) {
        puts("invalid size");
        exit(1);
    }

    allocs[idx] = malloc(size);
    sizes[idx] = size;

    printf("allocated %d bytes at index %d\n", size, idx);
}



void kiwi() {
    int idx = 0;
    int offset = 0;

    printf("index: ");
    scanf("%d", &idx);

    if (idx < 0 || idx >= 10) {
        puts("invalid index");
        exit(1);
    }

    printf("offset: ");
    scanf("%d", &offset);

    if (offset < 0 || offset >= sizes[idx]) {
        puts("invalid offset");
        exit(1);
    }

    printf("data: ");
    read(0, allocs[idx] + offset, sizes[idx]);

    puts("done");
}



void mango() {
    int idx = 0;

    printf("index: ");
    scanf("%d", &idx);

    if (idx < 0 || idx >= 10) {
        puts("invalid index");
        exit(1);
    }

    if (allocs[idx] == NULL) {
        puts("no data");
        return;
    }

    printf("data: %s\n", allocs[idx]);
}


void orange() {
    puts("heap with no oranges should be secure, right?");
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
                avocado();
                break;
            case 2:
                kiwi();
                break;
            case 3:
                orange();
                break;
            case 4:
                mango();
                break;
            case 5: return;
            default:
                puts("Invalid choice");
                exit(1);
        }

    }


}