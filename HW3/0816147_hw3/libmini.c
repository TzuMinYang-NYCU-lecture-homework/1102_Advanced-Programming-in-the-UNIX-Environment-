#include "libmini.h"

long errno;

#define WRAPPER_RETval(type)    errno = 0; if(ret < 0) { errno = -ret; return -1; } return ((type) ret);
#define WRAPPER_RETptr(type)    errno = 0; if(ret < 0) { errno = -ret; return NULL; } return ((type) ret);

ssize_t read(int fd, char *buf, size_t count) {
        long ret = sys_read(fd, buf, count);
        WRAPPER_RETval(ssize_t);
}

ssize_t write(int fd, const void *buf, size_t count) {
        long ret = sys_write(fd, buf, count);
        WRAPPER_RETval(ssize_t);
}

/* open is implemented in assembly, because of variable length arguments */

int     close(unsigned int fd) {
        long ret = sys_close(fd);
        WRAPPER_RETval(int);
}

void *  mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
        long ret = sys_mmap(addr, len, prot, flags, fd, off);
        WRAPPER_RETptr(void *);
}

int     mprotect(void *addr, size_t len, int prot) {
            long ret = sys_mprotect(addr, len, prot);
        WRAPPER_RETval(int);
}

int     munmap(void *addr, size_t len) {
        long ret = sys_munmap(addr, len);
        WRAPPER_RETval(int);
}

int     sigaction(int sig, struct sigaction *act, struct sigaction *oact){ // add by myself, const should be removed
        act->sa_flags |= SA_RESTORER;
	act->sa_restorer = sys_rt_sigreturn; // 不能用C++的function
        long ret = sys_rt_sigaction(sig, act, oact, sizeof(sigset_t));
        WRAPPER_RETval(int);
}

int     sigprocmask(int how, sigset_t *set, sigset_t *oldset){ // add by myself, const delete by myself
        long ret = sys_rt_sigprocmask(how, set, oldset, sizeof(sigset_t));
        WRAPPER_RETval(int);
}

void    sigreturn(){ // add by myself , sa_restorer不能用C++的function
        sys_rt_sigreturn();
}

int     pipe(int *filedes) {
        long ret = sys_pipe(filedes);
        WRAPPER_RETval(int);
}

int     dup(int filedes) {
        long ret = sys_dup(filedes);
        WRAPPER_RETval(int);
}

int     dup2(int oldfd, int newfd) {
        long ret = sys_dup2(oldfd, newfd);
        WRAPPER_RETval(int);
}

int     pause() {
        long ret = sys_pause();
        WRAPPER_RETval(int);
}

int     nanosleep(struct timespec *rqtp, struct timespec *rmtp) {
        long ret = sys_nanosleep(rqtp, rmtp);
        WRAPPER_RETval(int);
}


int     alarm(unsigned int seconds) {  // add by myself
        long ret = sys_alarm(seconds);
        WRAPPER_RETval(int);
}

pid_t   fork(void) {
        long ret = sys_fork();
        WRAPPER_RETval(pid_t);
}

void    exit(int error_code) {
        sys_exit(error_code);
        /* never returns? */
}

char *  getcwd(char *buf, size_t size) {
        long ret = sys_getcwd(buf, size);
        WRAPPER_RETptr(char *);
}

int     chdir(const char *pathname) {
        long ret = sys_chdir(pathname);
        WRAPPER_RETval(int);
}

int     rename(const char *oldname, const char *newname) {
        long ret = sys_rename(oldname, newname);
        WRAPPER_RETval(int);
}

int     mkdir(const char *pathname, int mode) {
        long ret = sys_mkdir(pathname, mode);
        WRAPPER_RETval(int);
}

int     rmdir(const char *pathname) {
        long ret = sys_rmdir(pathname);
        WRAPPER_RETval(int);
}

int     creat(const char *pathname, int mode) {
        long ret = sys_creat(pathname, mode);
        WRAPPER_RETval(int);
}

int     link(const char *oldname, const char *newname) {
        long ret = sys_link(oldname, newname);
        WRAPPER_RETval(int);
}

int     unlink(const char *pathname) {
        long ret = sys_unlink(pathname);
        WRAPPER_RETval(int);
}

ssize_t readlink(const char *path, char *buf, size_t bufsz) {
        long ret = sys_readlink(path, buf, bufsz);
        WRAPPER_RETval(ssize_t);
}

int     chmod(const char *filename, mode_t mode) {
       long ret = sys_chmod(filename, mode);
        WRAPPER_RETval(int);
}

int     chown(const char *filename, uid_t user, gid_t group) {
        long ret = sys_chown(filename, user, group);
        WRAPPER_RETval(int);
}

int     umask(int mask) {
        long ret = sys_umask(mask);
        WRAPPER_RETval(int);
}

int     gettimeofday(struct timeval *tv, struct timezone *tz) {
        long ret = sys_gettimeofday(tv, tz);
        WRAPPER_RETval(int);
}

uid_t   getuid() {
        long ret = sys_getuid();
        WRAPPER_RETval(uid_t);
}

gid_t   getgid() {
        long ret = sys_getgid();
        WRAPPER_RETval(gid_t);
}

int     setuid(uid_t uid) {
       long ret = sys_setuid(uid);
        WRAPPER_RETval(int);
}

int     setgid(gid_t gid) {
        long ret = sys_setgid(gid);
        WRAPPER_RETval(int);
}

uid_t   geteuid() {
        long ret = sys_geteuid();
        WRAPPER_RETval(uid_t);
}

gid_t   getegid() {
        long ret = sys_getegid();
        WRAPPER_RETval(uid_t);
}

void bzero(void *s, size_t size) {
        char *ptr = (char *) s;
        while(size-- > 0) *ptr++ = '\0';
}

size_t strlen(const char *s) {
        size_t count = 0;
        while(*s++) count++;
        return count;
}

int     sigpending(sigset_t *set){ // add by myself
        long ret = sys_rt_sigpending(set, sizeof(sigset_t));
        WRAPPER_RETval(int);
}

#define PERRMSG_MIN     0
#define PERRMSG_MAX     34

static const char *errmsg[] = {
        "Success",
        "Operation not permitted",
        "No such file or directory",
        "No such process",
        "Interrupted system call",
        "I/O error",
        "No such device or address",
        "Argument list too long",
        "Exec format error",
        "Bad file number",
        "No child processes",
        "Try again",
        "Out of memory",
        "Permission denied",
        "Bad address",
        "Block device required",
        "Device or resource busy",
        "File exists",
        "Cross-device link",
        "No such device",
        "Not a directory",
        "Is a directory",
        "Invalid argument",
        "File table overflow",
        "Too many open files",
        "Not a typewriter",
        "Text file busy",
        "File too large",
        "No space left on device",
        "Illegal seek",
        "Read-only file system",
        "Too many links",
        "Broken pipe",
        "Math argument out of domain of func",
        "Math result not representable"
};

void perror(const char *prefix) {
        const char *unknown = "Unknown";
        long backup = errno;
        if(prefix) {
                write(2, prefix, strlen(prefix));
                write(2, ": ", 2);
        }
        if(errno < PERRMSG_MIN || errno > PERRMSG_MAX) write(2, unknown, strlen(unknown));
        else write(2, errmsg[backup], strlen(errmsg[backup]));
        write(2, "\n", 1);
        return;
}

#if 0   /* we have an equivalent implementation in assembly */
unsigned int sleep(unsigned int seconds) {
        long ret;
        struct timespec req, rem;
        req.tv_sec = seconds;
        req.tv_nsec = 0;
        ret = sys_nanosleep(&req, &rem);
        if(ret >= 0) return ret;
        if(ret == -EINTR) {
                return rem.tv_sec;
        }
        return 0;
}
#endif

// add by myself

int sigaddset(sigset_t *set, int _sig) // 本來開頭有static inline, 被我刪掉了
{
	unsigned long sig = _sig - 1;
	if (_NSIG_WORDS == 1)
		set->sig[0] |= 1UL << sig;
	else
		set->sig[sig / _NSIG_BPW] |= 1UL << (sig % _NSIG_BPW);
    return 0;
}

int sigdelset(sigset_t *set, int _sig) // 本來開頭有static inline, 被我刪掉了
{
	unsigned long sig = _sig - 1;
	if (_NSIG_WORDS == 1)
		set->sig[0] &= ~(1UL << sig);
	else
		set->sig[sig / _NSIG_BPW] &= ~(1UL << (sig % _NSIG_BPW));
    return 0;
}

int sigismember(sigset_t *set, int _sig) // 本來開頭有static inline, 被我刪掉了
{
	unsigned long sig = _sig - 1;
	if (_NSIG_WORDS == 1)
		return 1 & (set->sig[0] >> sig);
	else
		return 1 & (set->sig[sig / _NSIG_BPW] >> (sig % _NSIG_BPW));
    return 0;
}

int sigemptyset(sigset_t *set) // 本來開頭有static inline, 被我刪掉了
{
	switch (_NSIG_WORDS) {
        default:
            //memset(set, 0, sizeof(sigset_t));
            bzero(set, sizeof(sigset_t));
            break;
        case 2: set->sig[1] = 0;
        case 1:	set->sig[0] = 0;
            break;
	}
    return 0;
}

int sigfillset(sigset_t *set) // 本來開頭有static inline, 被我刪掉了
{
	switch (_NSIG_WORDS) {
        default:
            //memset(set, -1, sizeof(sigset_t));
            for(int i = 0; i < sizeof(sigset_t) / sizeof(unsigned long); i++) //!!! not sure
                set->sig[i] = -1;
            break;
        case 2: set->sig[1] = -1;
        case 1:	set->sig[0] = -1;
            break;
	}
    return 0;
}

sighandler_t signal(int signum, sighandler_t handler) // 照投影片CH10 p43, 只是有的功能不會用到就直接不寫了
{
    struct sigaction new_act, old_act;
    new_act.sa_handler = handler;
    new_act.sa_flags = 0;
    sigemptyset(&new_act.sa_mask);

    if(sigaction(signum, &new_act, &old_act) < 0)
        return(SIG_ERR);
    return (old_act.sa_handler);
}

// setjump and longjump

sigset_t get_cur_mask()
{
    sigset_t mask, oldmask;
    sigprocmask(SIG_SETMASK, &mask, &oldmask);
    sigprocmask(SIG_SETMASK, &oldmask, &mask);
    return oldmask;
}

int setjmp(jmp_buf env)
{
    asm_setjmp(env);
    env->mask = get_cur_mask();
    return 0;
}
void longjmp(jmp_buf env, int val)
{
    sigprocmask(SIG_SETMASK, &(env->mask), NULL);
    asm_longjmp(env, val);
}

// end of add