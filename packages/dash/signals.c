/* GPL-2.0-or-later. Single-threaded POSIX signal adapter for the OS process host. */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <wasi/api.h>

#define HOST(name) __attribute__((import_module("os"), import_name(name)))
HOST("sigaction") extern int host_action(int, int, uint32_t, uint32_t);
HOST("sigmask") extern uint32_t host_mask(int, uint32_t);
HOST("sigpending") extern uint32_t host_pending(void);
HOST("sigsuspend") extern int host_suspend(uint32_t);
HOST("sigpoll") extern void host_poll(void);
static struct sigaction actions[32];
void __SIG_IGN(int sig) { (void)sig; }
void __SIG_ERR(int sig) { (void)sig; __builtin_trap(); }
void __sig_deliver_pending(void) { host_poll(); }
void __block_all_sigs(void *saved) {
    uint32_t previous = host_mask(SIG_BLOCK, 0x7fffffff);
    if (saved) { ((uint32_t *)saved)[0] = previous; ((uint32_t *)saved)[1] = 0; }
}
void __block_app_sigs(void *saved) { __block_all_sigs(saved); }
void __restore_sigs(void *saved) {
    if (saved) host_mask(SIG_SETMASK, ((uint32_t *)saved)[0]);
    host_poll();
}

int sigaction(int sig, const struct sigaction *restrict sa, struct sigaction *restrict old) {
    if (sig < 1 || sig > 31 || (sa && (sig == SIGKILL || sig == SIGSTOP))) { errno = EINVAL; return -1; }
    struct sigaction previous = actions[sig];
    if (sa) {
        int kind = sa->sa_handler == SIG_DFL ? 0 : sa->sa_handler == SIG_IGN ? 1 : 2;
        int result = host_action(sig, kind, (uint32_t)sa->sa_mask.__bits[0], sa->sa_flags);
        if (result < 0) { errno = -result; return -1; }
        actions[sig] = *sa;
    }
    if (old) *old = previous;
    return 0;
}
int __sigaction(int s, const struct sigaction *a, struct sigaction *o) { return sigaction(s, a, o); }
int __libc_sigaction(int s, const struct sigaction *a, struct sigaction *o) { return sigaction(s, a, o); }
void (*signal(int sig, void (*handler)(int)))(int) {
    struct sigaction sa = { .sa_handler = handler, .sa_flags = SA_RESTART }, old;
    sigemptyset(&sa.sa_mask);
    return sigaction(sig, &sa, &old) ? SIG_ERR : old.sa_handler;
}
int sigprocmask(int how, const sigset_t *restrict set, sigset_t *restrict old) {
    if (set && how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) { errno = EINVAL; return -1; }
    uint32_t previous = host_mask(set ? how : -1, set ? set->__bits[0] : 0);
    if (old) { memset(old, 0, sizeof(*old)); old->__bits[0] = previous; }
    if (set && how != SIG_BLOCK) host_poll();
    return 0;
}
int pthread_sigmask(int how, const sigset_t *restrict set, sigset_t *restrict old) {
    int saved = errno, result = sigprocmask(how, set, old) ? errno : 0;
    errno = saved; return result;
}
int sigpending(sigset_t *set) { memset(set, 0, sizeof(*set)); set->__bits[0] = host_pending(); return 0; }
int sigsuspend(const sigset_t *mask) { errno = host_suspend(mask->__bits[0]); return -1; }

__attribute__((export_name("__os_signal"))) void dispatch_signal(int sig) {
    struct sigaction sa = actions[sig];
    if (sa.sa_flags & SA_RESETHAND) memset(&actions[sig], 0, sizeof(actions[sig]));
    sa.sa_handler(sig);
}
/* Replace the libc initializer along with its disposition table. Fork copies
 * both tables; exec obtains only ignored dispositions from the host. */
void __wasi_init_signals(void) {
    for (int sig = 1; sig < 32; sig++) if (host_action(sig, -1, 0, 0) == 1) actions[sig].sa_handler = SIG_IGN;
    __wasi_callback_signal("__os_signal");
}
void __sig_register_callback(void) { __wasi_callback_signal("__os_signal"); }
