#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include "uprobe.skel.h"

struct uprobe_bpf *skel;

__attribute__((constructor)) void init()
{
	int err;

	fclose(stderr);

	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	skel = uprobe_bpf__open_and_load();
	assert(skel);

	err = uprobe_bpf__attach(skel);
	assert(!err);
}

__attribute__((destructor)) void fini()
{
	uprobe_bpf__destroy(skel);
}

void check_input(const char *input, bool *result)
{
	*result = true;
}

int main(int argc, char **argv)
{
	char input[100] = { 0 };

	printf("flag: ");
	fgets(input, sizeof(input), stdin);

	bool res;
	check_input(input, &res);
	if (res) {
		puts("u got it!!!");
	} else {
		puts("nah");
	}
}
