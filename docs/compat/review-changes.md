# PR #66 review measurement changes

Compared with the original PR baseline at `46afafe`. No runtime behavior was fixed. 20 rows changed their normalized trace, and 10 additional rows changed classification only. The revised matrix has 135 rows: 19 matching filesystem traces, 101 filesystem differences/skips, and 15 process observations.

Path identities now use ABI Stat; absent device/inode fields are unavailable. Retained-fd identity uses separate device/inode observations and rejects Preview 1's constant device value and zero-inode fallback. Native startup details moved to environmental evidence; OS startup records source-launch flags rather than silently assuming them. Filesystem improvements are not implied by these measurement corrections.

| Row | Changed steps | Classification |
| --- | --- | --- |
| cloud/open-rename | Linux: identity; OS: identity | same → difference/skip |
| cloud/open-unlink | Linux: identity; OS: identity | difference/skip → difference/skip |
| cloud/hard-link | OS: identity | same → difference/skip |
| cloud/startup | Linux: ownership, pid1, unavailable; OS: ownership | difference/skip → observational |
| browser-storage/alias | OS: identity | difference/skip → difference/skip |
| browser-storage/open-rename | Linux: identity; OS: identity | difference/skip → difference/skip |
| browser-storage/open-unlink | Linux: identity; OS: identity | difference/skip → difference/skip |
| browser-storage/startup | Linux: ownership, pid1, unavailable; OS: ownership | difference/skip → observational |
| directory-handle/alias | OS: identity | difference/skip → difference/skip |
| directory-handle/open-rename | Linux: identity; OS: identity | difference/skip → difference/skip |
| directory-handle/open-unlink | Linux: identity; OS: identity | difference/skip → difference/skip |
| directory-handle/startup | Linux: ownership, pid1, unavailable; OS: ownership | difference/skip → observational |
| local-helper/alias | OS: identity | difference/skip → difference/skip |
| local-helper/open-rename | Linux: identity; OS: identity | same → difference/skip |
| local-helper/open-unlink | Linux: identity; OS: identity | difference/skip → difference/skip |
| local-helper/startup | Linux: ownership, pid1, unavailable; OS: ownership | difference/skip → observational |
| relay/alias | OS: identity | difference/skip → difference/skip |
| relay/open-rename | Linux: identity | difference/skip → difference/skip |
| relay/open-unlink | Linux: identity | difference/skip → difference/skip |
| relay/startup | Linux: ownership, pid1, unavailable; OS: ownership | difference/skip → observational |

These rows have unchanged observations but no comparable native GUI/browser fixture, so they are tracked as observations rather than permanent Linux differences:

| Row | Changed steps | Classification |
| --- | --- | --- |
| cloud/gui-processes | Trace unchanged; classification corrected | difference/skip → observational |
| cloud/tab-pids | Trace unchanged; classification corrected | difference/skip → observational |
| browser-storage/gui-processes | Trace unchanged; classification corrected | difference/skip → observational |
| browser-storage/tab-pids | Trace unchanged; classification corrected | difference/skip → observational |
| directory-handle/gui-processes | Trace unchanged; classification corrected | difference/skip → observational |
| directory-handle/tab-pids | Trace unchanged; classification corrected | difference/skip → observational |
| local-helper/gui-processes | Trace unchanged; classification corrected | difference/skip → observational |
| local-helper/tab-pids | Trace unchanged; classification corrected | difference/skip → observational |
| relay/gui-processes | Trace unchanged; classification corrected | difference/skip → observational |
| relay/tab-pids | Trace unchanged; classification corrected | difference/skip → observational |

All Linux cold/warm timings were regenerated with a release probe instead of debug; all OS timings were rerun. `linux-evidence.json` now holds host startup facts/errors. Both evidence files record the measured checkout HEAD and dirty flag, and the OS runner rebuilds web assets before measuring.
