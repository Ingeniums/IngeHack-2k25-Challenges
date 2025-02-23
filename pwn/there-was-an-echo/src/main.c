# define _GNU_SOURCE
# include <stdio.h>
# include <stdlib.h>
# include <seccomp.h>


# define BUFF_SIZE 0x100


void init() {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);

    if (ctx == NULL) {
        exit(1);
    }

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    if (seccomp_load(ctx) < 0) {
        seccomp_release(ctx);
        exit(1);
    }
    seccomp_release(ctx);
}

void main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    init();
    char buf[BUFF_SIZE];
    while (1) {
        fgets(buf, BUFF_SIZE, stdin);
        printf(buf);
    }
}