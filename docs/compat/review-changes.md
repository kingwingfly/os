# PR #66 review measurement changes

Compared with commit `2455e96`, the commit reviewed in this round. No runtime semantics were changed. **15 rows changed normalized traces and two additional rows changed comparison results only.** The matrix contains 135 rows: **16 matching filesystem traces, 104 differences/skips, and 15 process observations**.

The new results remove five unsupported matches (four single-account creation rows and cloud two-accounts). Two retained-file rows now match on observable fields; their raw unavailable device identity remains visible. These are measurement corrections, not runtime improvements or regressions.

| Row | Changed evidence | Result before → after |
| --- | --- | --- |
| cloud/open-rename | Comparison only: exclude unobservable fd st_dev; retain raw evidence and compare inode/calls/errors. | difference/skip → same |
| cloud/creation | Stat directory mode/group; explicitly skip inheritance when creator group equals directory group. | same → difference/skip |
| cloud/two-accounts | Measure directory mode/group, supplementary groups and inheritance; native A now uses a distinct directory group; OS A inheritance is unavailable. | same → difference/skip |
| cloud/startup | Replace source-text flags with live init/login lease ownership and a real managed supervisor. | observation → observation |
| browser-storage/creation | Stat directory mode/group; explicitly skip inheritance when creator group equals directory group. | same → difference/skip |
| browser-storage/two-accounts | Measure directory mode/group, supplementary groups and inheritance; native A now uses a distinct directory group; OS A inheritance is unavailable. | difference/skip → difference/skip |
| browser-storage/startup | Replace source-text flags with live init/login lease ownership and a real managed supervisor. | observation → observation |
| directory-handle/creation | Stat directory mode/group; explicitly skip inheritance when creator group equals directory group. | same → difference/skip |
| directory-handle/two-accounts | Measure directory mode/group, supplementary groups and inheritance; native A now uses a distinct directory group; OS A inheritance is unavailable. | difference/skip → difference/skip |
| directory-handle/startup | Replace source-text flags with live init/login lease ownership and a real managed supervisor. | observation → observation |
| local-helper/open-rename | Comparison only: exclude unobservable fd st_dev; retain raw evidence and compare inode/calls/errors. | difference/skip → same |
| local-helper/creation | Stat directory mode/group; explicitly skip inheritance when creator group equals directory group. | same → difference/skip |
| local-helper/two-accounts | Measure directory mode/group, supplementary groups and inheritance; native A now uses a distinct directory group; OS A inheritance is unavailable. | difference/skip → difference/skip |
| local-helper/startup | Replace source-text flags with live init/login lease ownership and a real managed supervisor. | observation → observation |
| relay/creation | Stat directory mode/group; explicitly skip inheritance when creator group equals directory group. | difference/skip → difference/skip |
| relay/two-accounts | Measure directory mode/group, supplementary groups and inheritance; native A now uses a distinct directory group; OS A inheritance is unavailable. | difference/skip → difference/skip |
| relay/startup | Replace source-text flags with live init/login lease ownership and a real managed supervisor. | observation → observation |

All other normalized row results are unchanged. Held-unmount rows are stored with append order instead of positional insertion; comparison has always sorted steps, so that storage-order cleanup is not a result change. All retained-fd rows now label the device comparison limit in the table, including rows that still differ on inode or I/O behavior.

Linux partial mappings, denied supplementary-group clearing, the no-namespace fallback and symlinked TMPDIR are covered by the explicit native regression gate. They do not change this host’s fully mapped reference profile.

The recorded target runs name source commit `e9b6529`; the dirty flag is true because generated docs/compat artifacts were being replaced. Harness/runtime sources were committed before those runs. Timings are separate and are not used for equality.
