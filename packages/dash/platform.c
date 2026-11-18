/* WASIX libc integration for the single-threaded OS process host. */
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wasi/api.h>
#include <wasi/libc-find-relpath.h>
#include <wasi/libc.h>

/* Reserved host pseudo-descriptors matching `abi::OS_FD_ROOT` / `abi::OS_FD_CWD`. */
#define OS_FD_ROOT 0x7ffffffd
#define OS_FD_CWD  0x7ffffffe

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
    (void)__wasi_fd_close(target);
    __wasi_fd_t result;
    error = __wasi_fd_dup2(source, target, 0, &result);
    if (error) { errno = error; return -1; }
    return result;
}

/* Fixed 80-byte raw statfs buffer matching `crates/posix/src/wasi_libc.rs`. */
struct os_raw_statfs {
    uint64_t f_type;
    uint64_t f_bsize;
    uint64_t f_frsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    uint64_t f_namelen;
    uint64_t f_flags;
};

/* Host-side process working directory, root jail, mount table, and namespaces. */
HOST("chdir") extern int host_chdir(const char *, size_t);
HOST("fchdir") extern int host_fchdir(int);
HOST("getcwd") extern int host_getcwd(char *, size_t);
HOST("chroot") extern int host_chroot(const char *, size_t);
HOST("mount") extern int host_mount(
    const char *, size_t,
    const char *, size_t,
    const char *, size_t,
    uint64_t,
    const char *, size_t
);
HOST("umount2") extern int host_umount2(const char *, size_t, uint32_t);
HOST("statfs") extern int host_statfs(const char *, size_t, struct os_raw_statfs *);
HOST("fstatfs") extern int host_fstatfs(int, struct os_raw_statfs *);
HOST("unshare") extern int host_unshare(uint32_t);
HOST("setns") extern int host_setns(int, uint32_t);

int chdir(const char *path) {
    if (!path) { errno = EFAULT; return -1; }
    return posix_result(host_chdir(path, strlen(path)));
}

int fchdir(int fd) {
    if (fd < 0) { errno = EBADF; return -1; }
    return posix_result(host_fchdir(fd));
}

char *getcwd(char *buf, size_t size) {
    if (buf) {
        if (size == 0) { errno = EINVAL; return NULL; }
        int rc = host_getcwd(buf, size);
        if (rc < 0) { errno = -rc; return NULL; }
        if ((size_t)rc == 0 || (size_t)rc > size) { errno = ERANGE; return NULL; }
        buf[rc - 1] = '\0';
        return buf;
    }
    if (size != 0) {
        char *alloc = malloc(size);
        if (!alloc) { errno = ENOMEM; return NULL; }
        int rc = host_getcwd(alloc, size);
        if (rc < 0) { free(alloc); errno = -rc; return NULL; }
        if ((size_t)rc == 0 || (size_t)rc > size) { free(alloc); errno = ERANGE; return NULL; }
        alloc[rc - 1] = '\0';
        return alloc;
    }
    for (size_t cap = 256; cap <= 65536; cap *= 2) {
        char *alloc = malloc(cap);
        if (!alloc) { errno = ENOMEM; return NULL; }
        int rc = host_getcwd(alloc, cap);
        if (rc == -ERANGE) { free(alloc); continue; }
        if (rc < 0) { free(alloc); errno = -rc; return NULL; }
        if ((size_t)rc == 0 || (size_t)rc > cap) { free(alloc); errno = ERANGE; return NULL; }
        alloc[rc - 1] = '\0';
        char *shrunk = realloc(alloc, (size_t)rc);
        return shrunk ? shrunk : alloc;
    }
    errno = ERANGE;
    return NULL;
}

int chroot(const char *path) {
    if (!path) { errno = EFAULT; return -1; }
    return posix_result(host_chroot(path, strlen(path)));
}

int mount(
    const char *source,
    const char *target,
    const char *filesystemtype,
    unsigned long mountflags,
    const void *data
) {
    if (!target) { errno = EFAULT; return -1; }
    const char *src = source ? source : (const char *)(uintptr_t)0;
    size_t src_len = source ? strlen(source) : 0;
    const char *fst = filesystemtype ? filesystemtype : (const char *)(uintptr_t)0;
    size_t fst_len = filesystemtype ? strlen(filesystemtype) : 0;
    const char *dat = data ? (const char *)data : (const char *)(uintptr_t)0;
    size_t dat_len = data ? strlen((const char *)data) : 0;
    return posix_result(host_mount(
        src, src_len,
        target, strlen(target),
        fst, fst_len,
        (uint64_t)mountflags,
        dat, dat_len
    ));
}

int umount2(const char *target, int flags) {
    if (!target) { errno = EFAULT; return -1; }
    return posix_result(host_umount2(target, strlen(target), (uint32_t)flags));
}

int umount(const char *target) {
    return umount2(target, 0);
}

int statfs(const char *path, struct os_raw_statfs *buf) {
    if (!path || !buf) { errno = EFAULT; return -1; }
    return posix_result(host_statfs(path, strlen(path), buf));
}

int fstatfs(int fd, struct os_raw_statfs *buf) {
    if (fd < 0) { errno = EBADF; return -1; }
    if (!buf) { errno = EFAULT; return -1; }
    return posix_result(host_fstatfs(fd, buf));
}

static void fill_statvfs(struct statvfs *dst, const struct os_raw_statfs *src) {
    memset(dst, 0, sizeof(*dst));
    dst->f_bsize = (unsigned long)src->f_bsize;
    dst->f_frsize = (unsigned long)(src->f_frsize ? src->f_frsize : src->f_bsize);
    dst->f_blocks = src->f_blocks;
    dst->f_bfree = src->f_bfree;
    dst->f_bavail = src->f_bavail;
    dst->f_files = src->f_files;
    dst->f_ffree = src->f_ffree;
    dst->f_favail = src->f_ffree;
    dst->f_fsid = 0;
    dst->f_flag = (unsigned long)src->f_flags;
    dst->f_namemax = (unsigned long)src->f_namelen;
}

int statvfs(const char *__restrict path, struct statvfs *__restrict buf) {
    if (!path || !buf) { errno = EFAULT; return -1; }
    struct os_raw_statfs raw;
    if (posix_result(host_statfs(path, strlen(path), &raw)) < 0) return -1;
    fill_statvfs(buf, &raw);
    return 0;
}

int fstatvfs(int fd, struct statvfs *buf) {
    if (fd < 0) { errno = EBADF; return -1; }
    if (!buf) { errno = EFAULT; return -1; }
    struct os_raw_statfs raw;
    if (posix_result(host_fstatfs(fd, &raw)) < 0) return -1;
    fill_statvfs(buf, &raw);
    return 0;
}

int unshare(int flags) {
    return posix_result(host_unshare((uint32_t)flags));
}

int setns(int fd, int nstype) {
    if (fd < 0) { errno = EBADF; return -1; }
    return posix_result(host_setns(fd, (uint32_t)nstype));
}

/* Route absolute paths through OS_FD_ROOT and relative paths through OS_FD_CWD
 * without calling getcwd() or collapsing `.` / `..` in guest memory. */
volatile int __wasilibc_populate_preopens_init = 1;

int __wasilibc_register_preopened_fd(int fd, const char *prefix) {
    (void)fd;
    (void)prefix;
    return 0;
}

int __wasilibc_find_abspath(
    const char *path,
    const char **__restrict__ abs_prefix,
    const char **__restrict__ relative_path
) {
    if (!path) { errno = EFAULT; return -1; }
    if (path[0] == '\0') { errno = ENOENT; return -1; }
    const char *rel = path;
    while (*rel == '/') rel++;
    if (*rel == '\0') rel = "/";
    if (abs_prefix) *abs_prefix = "";
    if (relative_path) *relative_path = rel;
    return OS_FD_ROOT;
}

int __wasilibc_find_relpath_alloc(
    const char *path,
    const char **abs_prefix,
    char **relative_path,
    size_t *relative_path_len,
    int can_realloc
) {
    if (!path || !relative_path || !relative_path_len) { errno = EFAULT; return -1; }
    if (path[0] == '\0') { errno = ENOENT; return -1; }
    int dirfd;
    const char *rel;
    if (path[0] == '/') {
        dirfd = OS_FD_ROOT;
        rel = path;
        while (*rel == '/') rel++;
        if (*rel == '\0') rel = "/";
    } else {
        dirfd = OS_FD_CWD;
        rel = path;
    }
    size_t need = strlen(rel) + 1;
    if (!*relative_path || *relative_path_len < need) {
        if (!can_realloc) { errno = ERANGE; return -1; }
        char *grown = realloc(*relative_path, need);
        if (!grown) { errno = ENOMEM; return -1; }
        *relative_path = grown;
        *relative_path_len = need;
    }
    memcpy(*relative_path, rel, need);
    if (abs_prefix) *abs_prefix = "";
    return dirfd;
}

int __wasilibc_find_relpath(
    const char *path,
    const char **__restrict__ abs_prefix,
    char **relative_path,
    size_t relative_path_len
) {
    size_t len = relative_path_len;
    return __wasilibc_find_relpath_alloc(path, abs_prefix, relative_path, &len, 0);
}
