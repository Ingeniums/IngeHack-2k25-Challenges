#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

inline void encrypt(unsigned int v[2], const unsigned int k[4])
{
	unsigned int v0 = v[0], v1 = v[1], sum = 0, i;
	unsigned int delta = 0x9E3779B9;
	unsigned int k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];

	for (i = 0; i < 32; i++) {
		sum += delta;
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
	}
	v[0] = v0;
	v[1] = v1;
}

unsigned int k[4] = { 0xbabab01, 0xcafebabe, 0xdeadbeef, 0x12344321 };

unsigned int x[] = { 0xc90c664,	 0xbe5424ab, 0x69098a34, 0x771e526d, 0x6ebb4c7c,
		     0x9835011e, 0xb69c60e0, 0xc749896f, 0xd494438a, 0xd26daa41,
		     0x8ab2b4c4, 0xd7818b8d, 0x70e4ee31, 0x7dbbaba,  0x8928ea5,
		     0x7e402d6b, 0x79c35bba, 0x23a9d90e, 0x44f84739, 0x9977e1ad };

SEC("uretprobe//proc/self/exe:check_input")
int BPF_KPROBE(checkinputproxy, char *inp, bool *result)
{
	int i;
	char input[100];
	bool r = false;
	unsigned int buf[2] = { 0 };

	bpf_probe_read_user(input, sizeof(input), inp);

	for (i = 0; i < 10; i += 1) {
		__builtin_memcpy(buf, input + i * 8, 8);
		encrypt(buf, k);
		if (__builtin_memcmp(buf, x + i * 2, 8)) {
			bpf_probe_write_user(result, &r, sizeof(bool));
			break;
		}
	}

_exit:
	return 0;
}
