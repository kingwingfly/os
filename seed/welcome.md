# OS

Access follows account, group, and rwx permissions. Anonymous visitors use guest.

```text
ls
open demo.slides.md
su root
groupadd research
useradd -m -G research alice
passwd alice
su - alice
touch notes.md
vim notes.md
exit
```

Passwords are entered in dialogs and never added to terminal history. Members of `wheel` can verify their own password to elevate an individual management command with `sudo`.

Drop files or use the upload button. Writes use your current account permissions, accept up to 100 MB per file, and do not overwrite existing names. Use `rm FILE` or `rm -r DIR` to remove content. Every command supports `-h`; `man` opens the manual.

Images, audio, video, and PDF have dedicated previews. Markdown opens in a reading view; `*.slides.md` uses a line containing only `---` to separate slides.

MP4 / MOV / M4V / M4A uploads are checked for faststart. When needed, run:

```bash
ffmpeg -i input.mp4 -c copy -movflags +faststart output.mp4
```
