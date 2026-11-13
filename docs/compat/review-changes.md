# PR #66 review measurement changes

Compared with reviewed commit `21e8bcc`. No OS runtime semantics were changed. **Eleven compatibility rows changed their evidence, with no classification changes**: ten rename/unlink rows and one GUI observation. The matrix still contains **120 filesystem rows (15 same and 105 differences/skips), plus three process observations**.

Descriptor identity is recorded in separate `identity-before` and `identity-after` rows. On Linux and the cloud/browser-storage/directory-handle/local-helper profiles, both calls succeed; existing device/inode availability and identity relations are unchanged. On relay, the before call succeeds and the after call returns ENOENT for both rename and unlink. The relation is now explicitly skipped instead of attributing that errno to an ambiguous combined step. Those differences retain their existing follow-up issues.

The GUI observation removes the hard-coded `mounts_opened`, `editor_opened` and `preview_opened` fields. The runner still asserts that each application opens before recording its actual process images; all measured process images and Files visibility are unchanged.

| Row | Changed steps | Result before → after |
| --- | --- | --- |
| cloud/open-rename | linux: identity-after, identity-before; os: identity-after, identity-before | difference/incomparable → difference/incomparable |
| cloud/open-unlink | linux: identity-after, identity-before; os: identity-after, identity-before | difference/incomparable → difference/incomparable |
| browser-storage/open-rename | linux: identity-after, identity-before; os: identity-after, identity-before | difference/incomparable → difference/incomparable |
| browser-storage/open-unlink | linux: identity-after, identity-before; os: identity-after, identity-before | difference/incomparable → difference/incomparable |
| directory-handle/open-rename | linux: identity-after, identity-before; os: identity-after, identity-before | difference/incomparable → difference/incomparable |
| directory-handle/open-unlink | linux: identity-after, identity-before; os: identity-after, identity-before | difference/incomparable → difference/incomparable |
| local-helper/open-rename | linux: identity-after, identity-before; os: identity-after, identity-before | difference/incomparable → difference/incomparable |
| local-helper/open-unlink | linux: identity-after, identity-before; os: identity-after, identity-before | difference/incomparable → difference/incomparable |
| relay/open-rename | linux: identity-after, identity-before; os: identity, identity-after, identity-before | difference/incomparable → difference/incomparable |
| relay/open-unlink | linux: identity-after, identity-before; os: identity, identity-after, identity-before | difference/incomparable → difference/incomparable |
| process/gui-processes | os: ps | observation → observation |

Every other normalized row is unchanged. No registry entry was added or removed; only the eleven reviewed signatures and the relay phase explanations changed.

## Latency and auxiliary evidence

The `stat-eight-deep` operation now performs one target stat, without the unrelated parent stat formerly used by ownership comparison. All five OS profiles and Linux have regenerated cold/warm samples. Linux `ls-usr-bin` now uses the timing tree as cwd, matching the documented OS scenario. These are measurement-method corrections, not runtime speedups; compare subsequent runs against the corrected samples. Other timing values are regenerated noisy evidence.

Compiler provenance now includes `package.json`. The prior cached image actually contained an older package manifest; it was rebuilt from the unchanged canonical Dockerfile before the OS runs. Every copied compiler source, both package manifests and locked Binaryen bytes are verified against the checkout. Linux panic output and OS signal/helper diagnostics are retained outside successful deterministic baselines. Validation commands and limits are in [README](README.md); the PR records the checks completed for this revision.
