#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <unistd.h>

int main(void) {
  char filename[256];
  uint64_t off;
  uint32_t val;

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("Enter the file name: ");
  scanf("%255s", filename);

  int file = open(filename, O_RDWR);
  assert(file > 0);

  printf("offset to write to: ");
  assert(scanf("%lu", &off));

  lseek(file, off, SEEK_SET);

  printf("value to write: ");
  assert(scanf("%u", &val));

  write(file, &val, sizeof(val));

  close(file);
}
