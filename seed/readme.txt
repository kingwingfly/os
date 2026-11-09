OS

Commands operate on an R2 virtual filesystem, never a host shell.

ls / cd / pwd / open / mkdir / rm / upload
su [-] [USER] / login / exit / sudo / passwd [--force]
chmod / chown / useradd / usermod / userdel / groupadd / groupmod / groupdel
whoami / id / groups / users / man / vim

Access follows owner/group/other rwx bits.
Root retains full control. Wheel members can authenticate with their own password to elevate explicit sudo commands.

touch [-c] FILE... creates empty files without changing existing content.
COMMAND -h / --help shows help. Ctrl+C clears the current input.
