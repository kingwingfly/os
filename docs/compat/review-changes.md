# PR #66 review measurement changes

Compared with reviewed commit `e433073`. No OS runtime semantics were changed. **23 filesystem rows changed normalized evidence**, and the same three process measurements moved from five duplicated profile copies into one independent section. The new matrix has **120 filesystem rows (17 matching traces and 103 differences/skips), plus three process observations**.

Linux now records both refused busy unmount and successful `umount2(MNT_DETACH)`. Its retained fd survives actual detach; cwd lookup returns ENOENT. OS records its existing detach separately from the unavailable busy-unmount API, then records re-attachment. Missing identity values now use structured markers; the comparison applies to every identity step. `cloud/hard-link` consequently matches on observable inode/call fields while device identity remains explicitly incomparable. This is a measurement correction, not a runtime improvement.

| Row | Changed steps | Result before → after |
| --- | --- | --- |
| cloud/open-rename | OS: identity | same → same |
| cloud/open-unlink | OS: identity | difference/skip → difference/skip |
| cloud/unmount-open | Linux: attach, detach, fstat, read | difference/skip → difference/skip |
| cloud/unmount-cwd | Linux: attach, detach, getcwd | difference/skip → difference/skip |
| cloud/hard-link | OS: identity | difference/skip → same |
| browser-storage/alias | OS: identity | difference/skip → difference/skip |
| browser-storage/open-rename | OS: identity | difference/skip → difference/skip |
| browser-storage/open-unlink | OS: identity | difference/skip → difference/skip |
| browser-storage/unmount-open | Linux: attach, detach, fstat, read; OS: attach, detach, fstat, read, unmount | difference/skip → difference/skip |
| browser-storage/unmount-cwd | Linux: attach, detach, getcwd; OS: attach, detach, getcwd, unmount | difference/skip → difference/skip |
| directory-handle/alias | OS: identity | difference/skip → difference/skip |
| directory-handle/open-rename | OS: identity | difference/skip → difference/skip |
| directory-handle/open-unlink | OS: identity | difference/skip → difference/skip |
| directory-handle/unmount-open | Linux: attach, detach, fstat, read; OS: attach, detach, fstat, read, unmount | difference/skip → difference/skip |
| directory-handle/unmount-cwd | Linux: attach, detach, getcwd; OS: attach, detach, getcwd, unmount | difference/skip → difference/skip |
| local-helper/alias | OS: identity | difference/skip → difference/skip |
| local-helper/open-rename | OS: identity | same → same |
| local-helper/open-unlink | OS: identity | difference/skip → difference/skip |
| local-helper/unmount-open | Linux: attach, detach, fstat, read; OS: attach, detach, fstat, read, unmount | difference/skip → difference/skip |
| local-helper/unmount-cwd | Linux: attach, detach, getcwd; OS: attach, detach, getcwd, unmount | difference/skip → difference/skip |
| relay/alias | OS: identity | difference/skip → difference/skip |
| relay/unmount-open | Linux: attach, detach, fstat, read; OS: attach, detach, fstat, read, unmount | difference/skip → difference/skip |
| relay/unmount-cwd | Linux: attach, detach, getcwd; OS: attach, detach, getcwd, unmount | difference/skip → difference/skip |

## Process rows consolidated without changing their results

Each old row below maps to the single new process row; all three normalized Linux/OS traces and signatures are unchanged. The 12 redundant copies are removed.

| Previous row | New row | Result |
| --- | --- | --- |
| cloud/startup | process/startup | unchanged observation |
| browser-storage/startup | process/startup | unchanged observation |
| directory-handle/startup | process/startup | unchanged observation |
| local-helper/startup | process/startup | unchanged observation |
| relay/startup | process/startup | unchanged observation |
| cloud/gui-processes | process/gui-processes | unchanged observation |
| browser-storage/gui-processes | process/gui-processes | unchanged observation |
| directory-handle/gui-processes | process/gui-processes | unchanged observation |
| local-helper/gui-processes | process/gui-processes | unchanged observation |
| relay/gui-processes | process/gui-processes | unchanged observation |
| cloud/tab-pids | process/tab-pids | unchanged observation |
| browser-storage/tab-pids | process/tab-pids | unchanged observation |
| directory-handle/tab-pids | process/tab-pids | unchanged observation |
| local-helper/tab-pids | process/tab-pids | unchanged observation |
| relay/tab-pids | process/tab-pids | unchanged observation |

The browser-storage `cross-rename` and `absolute-symlink` fixtures now cross into actual cloud storage, with source-only markers proving the trees are distinct. Their normalized outcomes remain EXDEV and ENOENT respectively. Other profiles also verify distinct crossing contents. The CDP drop no longer reaches the application upload handler. These isolation corrections do not otherwise change recorded results.

Both target runs measured source commit `015dbbf` with `dirty:false`. The dirty flag excludes the resolved output directory, including generated timings, while retaining source modifications. The helper is now built in release mode; all cold/warm timings were recollected and remain outside comparison signatures.
