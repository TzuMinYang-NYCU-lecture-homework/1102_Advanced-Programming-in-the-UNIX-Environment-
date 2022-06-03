#include "libmini.h"

static jmp_buf buf;

void handler(int s) {
    write(1, "handler()\n", 10);
    longjmp(buf, 1);
}

int main() {
    sigset_t s;
    sigemptyset(&s);
    // sigaddset(&s, SIGALRM);
    sigprocmask(SIG_BLOCK, &s, NULL);
    signal(SIGALRM, handler);
    int a = setjmp(buf);
    if (!a) {
        alarm(1);
        sleep(1);
    } else if (a == 1) {
        write(1, "a == 1\n", 7);
    } else {
        write(1, "else\n", 5);
    }
    write(1, "done\n", 5);
    return 0;
}