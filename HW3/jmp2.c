#include "libmini.h"

typedef void (*proc_t)();
static jmp_buf jb1;
static jmp_buf jb2;

#define FUNBODY(m, from, val)   \
    {                           \
        write(1, m, strlen(m)); \
        longjmp(from, val);     \
    }

void a() FUNBODY("This is function a().\n", jb1, 1);
void b() FUNBODY("This is function b().\n", jb1, 2);
void c() FUNBODY("This is function c().\n", jb1, 3);

void d() FUNBODY("This is function d().\n", jb2, 4);
void e() FUNBODY("This is function e().\n", jb2, 5);
void f() FUNBODY("This is function f().\n", jb2, 6);

proc_t funs1[] = {a, b, c};
proc_t funs2[] = {d, e, f};

int main() {
    volatile int i = 0, j = 0;
    if (setjmp(jb1) != 0) {
        i++;
    }

    if (setjmp(jb2) != 0) {
        j++;
    }
    if (j < 3) funs2[j]();
    j = 0;

    write(1, "---\n", 4);

    if (i < 3) funs1[i]();
    return 0;
}
