# PR #66 review measurement changes

Compared with reviewed commit `4c6640e`. No OS runtime semantics were changed. **Eight filesystem rows changed**: five have corrected two-account fixture evidence and three have a corrected identity classification. The matrix contains **120 filesystem rows (15 same and 105 differences/skips), plus three unchanged process observations**.

Both Linux and OS creators now have exactly one configured neutral supplementary group, also the setgid directory's group, distinct from both primary groups. Native setup clears inherited groups before installing that group; OS setup replaces account memberships before login and changes the directory group through ordinary owner permissions. Both creators can demonstrate inheritance. Cloud now matches Linux and its old registry entry is removed. The four private/export profiles still show B's EACCES, publisher ownership and zero-byte file; those runtime differences remain assigned to #49/#59.

Device and inode together identify an object. Missing device evidence no longer permits equality based on a coincident inode alone. Three previously matching rows become incomparable and are assigned to #48; their raw syscall traces did not change. This is a measurement correction, not a runtime regression or an architecture decision.

| Row | Changed steps | Result before → after |
| --- | --- | --- |
| cloud/open-rename | Comparison only; raw evidence unchanged | same → difference/incomparable |
| cloud/hard-link | Comparison only; raw evidence unchanged | same → difference/incomparable |
| cloud/two-accounts | linux: a-groups, b-groups; os: a-directory, a-inheritance, a-stat | difference/incomparable → same |
| browser-storage/two-accounts | linux: a-groups, b-groups; os: a-directory, a-inheritance, a-stat | difference/incomparable → difference/incomparable |
| directory-handle/two-accounts | linux: a-groups, b-groups; os: a-directory, a-inheritance, a-stat | difference/incomparable → difference/incomparable |
| local-helper/open-rename | Comparison only; raw evidence unchanged | same → difference/incomparable |
| local-helper/two-accounts | linux: a-groups, b-groups; os: a-directory, a-inheritance, a-stat | difference/incomparable → difference/incomparable |
| relay/two-accounts | linux: a-groups, b-groups; os: a-directory, a-inheritance, a-stat | difference/incomparable → difference/incomparable |

For all five two-account rows, Linux `a-groups`/`b-groups` now report the explicitly installed neutral supplementary membership. OS `a-directory` and `a-stat` show a group distinct from A's primary group; `a-inheritance` is measured successfully instead of skipped. B already had a distinct primary group; its creation evidence is unchanged. The fixture checks the exact supplementary membership before recording results.

Every other normalized row and all three process observations are unchanged. Signature ordering now uses fixed code-unit order; it did not alter the signatures of this baseline's other rows. Timing and host/provenance evidence are regenerated separately from deterministic observations. Validation commands and platform limits are documented in [README](README.md); the PR records the checks actually completed.
