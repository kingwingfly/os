/* WASIX libc integration for the single-threaded OS process host. */
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <string.h>
#include <wasi/api.h>
#include <wasi/libc.h>

#define HOST(name) __attribute__((import_module("os"), import_name(name)))
HOST("getuid") extern uid_t host_uid(void);
HOST("getgid") extern gid_t host_gid(void);
HOST("getgroups") extern int host_groups(int, gid_t *);
uid_t getuid(void) { return host_uid(); }
uid_t geteuid(void) { return host_uid(); }
gid_t getgid(void) { return host_gid(); }
gid_t getegid(void) { return host_gid(); }
int getgroups(int count, gid_t *groups) {
    int result = host_groups(count, groups);
    if (result < 0) { errno = -result; return -1; }
    return result;
}

/* The host implements signed wait selectors and POSIX job-state notifications. */
HOST("waitpid2") extern int host_waitpid(int, int *, unsigned);
pid_t waitpid(pid_t pid, int *status, int options) {
    int result = host_waitpid(pid, status, options);
    if (result < 0) { errno = -result; return -1; }
    return result;
}
HOST("getpgid") extern int host_getpgid(int);
HOST("getsid") extern int host_getsid(int);
HOST("setpgid") extern int host_setpgid(int, int);
HOST("setsid") extern int host_setsid(void);
HOST("tcgetpgrp") extern int host_tcgetpgrp(int);
HOST("tcsetpgrp") extern int host_tcsetpgrp(int, int);
static int posix_result(int result) {
    if (result < 0) { errno = -result; return -1; }
    return result;
}
pid_t getpgid(pid_t pid) { return posix_result(host_getpgid(pid)); }
pid_t getpgrp(void) { return getpgid(0); }
pid_t getsid(pid_t pid) { return posix_result(host_getsid(pid)); }
int setpgid(pid_t pid, pid_t pgid) { return posix_result(host_setpgid(pid, pgid)); }
int setpgrp(void) { return setpgid(0, 0); }
pid_t setsid(void) { return posix_result(host_setsid()); }
pid_t tcgetpgrp(int fd) { return posix_result(host_tcgetpgrp(fd)); }
int tcsetpgrp(int fd, pid_t pgid) { return posix_result(host_tcsetpgrp(fd, pgid)); }
int killpg(pid_t pgid, int sig) {
    if (pgid < 0) { errno = EINVAL; return -1; }
    return kill(-pgid, sig);
}
/* libc's wait4 applies syscall errno translation to waitpid's already
 * translated result, turning EINTR into EPERM. Preserve the original errno. */
pid_t wait4(pid_t pid, int *status, int options, struct rusage *usage) {
    pid_t result = waitpid(pid, status, options);
    if (result > 0 && usage) memset(usage, 0, sizeof(*usage));
    return result;
}
pid_t wait3(int *status, int options, struct rusage *usage) { return wait4(-1, status, options, usage); }

/* WASI renumber moves; POSIX dup2 keeps the source descriptor open. */
int dup2(int source, int target) {
    __wasi_fdstat_t stat;
    __wasi_errno_t error = __wasi_fd_fdstat_get(source, &stat);
    if (error) { errno = error; return -1; }
    if (target < 0) { errno = EBADF; return -1; }
    if (source == target) return target;
    __wasi_fd_close(target);
    __wasi_fd_t result;
    error = __wasi_fd_dup2(source, target, 0, &result);
    if (error) { errno = error; return -1; }
    return result;
}

/* A child may inherit ordinary fds before its preopens. The SDK constructor
 * stops at the first non-preopen; scan the host's bounded preopen range instead.
 * Register through libc's own table so normal path lookup stays in libc. */
volatile int __wasilibc_populate_preopens_init = 1;
__attribute__((constructor(51))) static void inherited_preopens(void) {
    for (__wasi_fd_t fd = 3; fd < 1024; fd++) {
        __wasi_prestat_t pre;
        if (__wasi_fd_prestat_get(fd, &pre)) continue;
        if (pre.tag != __WASI_PREOPENTYPE_DIR || pre.u.dir.pr_name_len > 4096) continue;
        size_t length = pre.u.dir.pr_name_len;
        char *name = malloc(length + 1);
        if (!name) _Exit(71);
        if (__wasi_fd_prestat_dir_name(fd, (uint8_t *)name, length)) { free(name); continue; }
        name[length] = 0;
        if (__wasilibc_register_preopened_fd(fd, name)) _Exit(71);
        free(name);
    }
}
