use super::{Manual, Section};
use clap::{ArgAction, Parser, Subcommand, ValueHint};

/// inspect, verify and activate immutable system releases
///
/// Staging verifies deployed signed artifacts. Activation changes the default for new
/// hosts; existing processes retain their generation. Rollback preserves mutable data.
#[derive(Parser, Debug)]
#[command(name = "imagectl")]
pub struct ImageCtl {
    #[command(subcommand)]
    pub action: Option<ImageAction>,
}
#[derive(Subcommand, Debug)]
pub enum ImageAction {
    /// inspect the selected release and retained generations
    Status,
    /// verify a deployed release without activating it
    Stage { release: String },
    /// select a verified release for new browser hosts
    Activate { release: String },
    /// return to an approved trusted release
    Rollback { release: String },
}
impl Manual for ImageCtl {
    const SECTION: Section = Section::Terminal;
    const NEEDS: &'static str = "Root for staging, activation and rollback; status is public.";
}

/// inspect or configure this account's container-provider policy
///
/// With no policy flags, prints the current policy. Changes use a revision check.
/// Active tasks retain their submission deadline; new admission and detach requests
/// use current policy. Closing an attached descriptor cancels its task.
#[derive(Parser, Debug)]
#[command(name = "providerctl")]
pub struct ProviderCtl {
    #[arg(long, default_value="/dev/archive", value_parser=["/dev/archive","/dev/media"])]
    pub device: String,
    /// allow new tasks
    #[arg(long, action=clap::ArgAction::Set)]
    pub enabled: Option<bool>,
    /// allow explicit detachment from descriptor lifetime
    #[arg(long, action=clap::ArgAction::Set)]
    pub detached: Option<bool>,
    /// maximum active tasks across this account's container devices (0 to 16)
    #[arg(long)]
    pub max_active: Option<u32>,
    /// absolute task deadline in seconds (1 to 604800)
    #[arg(long)]
    pub timeout: Option<u64>,
}
impl Manual for ProviderCtl {
    const SECTION: Section = Section::Terminal;
    const NEEDS: &'static str =
        "An authorized accelerator descriptor. Policy belongs to its controlling account.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[(
        "providerctl --detached false --max-active 4 --timeout 3600",
        "limit future container work",
    )];
}

/// mount a filesystem or list mounted filesystems
///
/// With no operands (or with `-t` only), lists visible mounts from `/proc/self/mountinfo`.
/// Otherwise attaches a new filesystem (`-t`), bind-mounts (`-B`/`-R`), moves (`-M`), remounts
/// (`-o remount,...`), or changes mount propagation (`--make-*`). Browser grants and osfs shares
/// use mountd, which authorizes the calling process.
#[derive(Parser, Debug)]
#[command(
    name = "mount",
    override_usage = "mount [-t FSTYPE]\n       mount [-t FSTYPE] [-o OPTS] [-r|-w] SOURCE TARGET\n       mount -B|-R|-M SOURCE TARGET\n       mount --make-private|--make-shared|--make-slave|--make-unbindable TARGET"
)]
pub struct Mount {
    /// filesystem type (for mounting or filtering listed mounts)
    #[arg(short = 't', long = "types", value_name = "FSTYPE")]
    pub types: Option<String>,
    /// comma-separated mount options (rw, ro, remount, bind, rbind, nosuid, nodev, noexec, fs data)
    #[arg(short = 'o', long = "options", value_name = "OPTS", action = ArgAction::Append)]
    pub options: Vec<String>,
    /// mount the filesystem read-only
    #[arg(short = 'r', long = "read-only")]
    pub read_only: bool,
    /// mount the filesystem read-write
    #[arg(short = 'w', long = "rw", visible_alias = "read-write")]
    pub read_write: bool,
    /// bind-mount a directory or file elsewhere
    #[arg(short = 'B', long = "bind")]
    pub bind: bool,
    /// recursively bind-mount a subtree and its submounts
    #[arg(short = 'R', long = "rbind")]
    pub rbind: bool,
    /// move an existing mountpoint to another location
    #[arg(short = 'M', long = "move")]
    pub move_mount: bool,
    /// mark mount propagation as private
    #[arg(long = "make-private")]
    pub make_private: bool,
    /// mark mount propagation as shared
    #[arg(long = "make-shared")]
    pub make_shared: bool,
    /// mark mount propagation as slave
    #[arg(long = "make-slave")]
    pub make_slave: bool,
    /// mark mount propagation as unbindable
    #[arg(long = "make-unbindable")]
    pub make_unbindable: bool,
    /// recursively mark mount propagation as private
    #[arg(long = "make-rprivate")]
    pub make_rprivate: bool,
    /// recursively mark mount propagation as shared
    #[arg(long = "make-rshared")]
    pub make_rshared: bool,
    /// recursively mark mount propagation as slave
    #[arg(long = "make-rslave")]
    pub make_rslave: bool,
    /// recursively mark mount propagation as unbindable
    #[arg(long = "make-runbindable")]
    pub make_runbindable: bool,
    /// source and/or target path
    #[arg(value_name = "PATH", value_hint = ValueHint::AnyPath, num_args = 0..=2)]
    pub operands: Vec<String>,
}
impl Manual for Mount {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "Root (uid 0) in the mount namespace; listing is public.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("mount", "list visible mounts"),
        ("mount -t tmpfs tmpfs /mnt", "mount a scratch tmpfs"),
        ("mount --bind /src /dst", "bind-mount a directory"),
        ("mount -o remount,ro /mnt", "remount read-only"),
    ];
    const SEE: &'static [&'static str] = &["umount", "findmnt", "df"];
}

/// unmount filesystems
///
/// Detaches one or more mounted filesystems at `TARGET...`. Busy mounts fail with `EBUSY` unless
/// `-l` (`--lazy`, `MNT_DETACH`) detaches the subtree while open references drain.
#[derive(Parser, Debug)]
#[command(name = "umount")]
pub struct Umount {
    /// detach the filesystem immediately and clean up when no longer busy
    #[arg(short = 'l', long = "lazy")]
    pub lazy: bool,
    /// request forced unmount
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    /// do not follow symlinks on the final mountpoint component
    #[arg(short = 'c', long = "no-canonicalize")]
    pub no_canonicalize: bool,
    /// mountpoint path(s) to unmount
    #[arg(value_name = "TARGET", value_hint = ValueHint::AnyPath, required = true)]
    pub targets: Vec<String>,
}
impl Manual for Umount {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "Root (uid 0) in the mount namespace.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("umount /mnt", "unmount a mountpoint"),
        ("umount -l /mnt", "lazy-detach a busy mount"),
    ];
    const SEE: &'static [&'static str] = &["mount", "findmnt", "df"];
}

/// find a filesystem or print the mount tree
///
/// Reads `/proc/self/mountinfo` and renders the mount hierarchy as a tree, flat list (`-l`), raw
/// space-separated rows (`-r`), or JSON (`-J`).
#[derive(Parser, Debug)]
#[command(name = "findmnt")]
pub struct Findmnt {
    /// format output as a flat list rather than a tree
    #[arg(short = 'l', long = "list")]
    pub list: bool,
    /// format output as JSON
    #[arg(short = 'J', long = "json")]
    pub json: bool,
    /// omit column headings
    #[arg(short = 'n', long = "noheadings")]
    pub noheadings: bool,
    /// use raw unpadded output
    #[arg(short = 'r', long = "raw")]
    pub raw: bool,
    /// comma-separated columns (TARGET,SOURCE,FSTYPE,OPTIONS,ID,PARENT,MAJ:MIN,PROPAGATION)
    #[arg(short = 'o', long = "output", value_name = "COLS")]
    pub output: Option<String>,
    /// filter by comma-separated filesystem types
    #[arg(short = 't', long = "types", value_name = "FSTYPE")]
    pub types: Option<String>,
    /// match an exact mountpoint directory
    #[arg(short = 'M', long = "mountpoint", value_name = "DIR", value_hint = ValueHint::DirPath)]
    pub mountpoint: Option<String>,
    /// find the mount containing a path
    #[arg(short = 'T', long = "target", value_name = "PATH", value_hint = ValueHint::AnyPath)]
    pub target: Option<String>,
    /// include submounts when filtering a mount
    #[arg(short = 'R', long = "submounts")]
    pub submounts: bool,
    /// optional mountpoint or target path
    #[arg(value_name = "TARGET", value_hint = ValueHint::AnyPath)]
    pub positional_target: Option<String>,
}
impl Manual for Findmnt {
    const SECTION: Section = Section::Files;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("findmnt", "display the mount tree"),
        ("findmnt -J", "emit the mount tree as JSON"),
        ("findmnt -T /usr/bin", "show which mount holds a path"),
    ];
    const SEE: &'static [&'static str] = &["mount", "umount", "df"];
}

/// run a command or interactive shell with a new root directory
///
/// Changes the root directory of this process to `NEWROOT`, changes the working directory to `/`,
/// and executes `COMMAND [ARG]...` (or `$SHELL -i`, falling back to `/bin/sh -i`).
#[derive(Parser, Debug)]
#[command(name = "chroot", override_usage = "chroot NEWROOT [COMMAND [ARG]...]")]
pub struct Chroot {
    /// directory to make the new process root
    #[arg(value_name = "NEWROOT", value_hint = ValueHint::DirPath)]
    pub newroot: String,
    /// command and arguments to run inside NEWROOT
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub command: Vec<String>,
}
impl Manual for Chroot {
    const SECTION: Section = Section::Terminal;
    const NEEDS: &'static str = "Root (uid 0).";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("chroot /jail /bin/sh -c pwd", "run a command inside /jail"),
        ("chroot /jail", "start an interactive shell inside /jail"),
    ];
    const SEE: &'static [&'static str] = &["mount", "umount"];
}

/// inspect, snapshot, scrub and manage os-cowfs volumes
///
/// Operates on mounted `os-cowfs` filesystems via `FS_IOC_COWFS_*` ioctls: inspect volume
/// metadata (`info`), manage read-only snapshots (`snapshot create|list|delete`), scrub Merkle
/// integrity (`scrub`), reclaim unreferenced blocks (`gc`), manage subvolumes (`subvol`), and
/// stream incremental backups (`send`, `receive`).
#[derive(Parser, Debug)]
#[command(
    name = "cowfs",
    override_usage = "cowfs info [PATH]\n       cowfs snapshot create|list|delete PATH [NAME]\n       cowfs scrub|gc [PATH]\n       cowfs subvol create|list|delete PATH [NAME]"
)]
pub struct Cowfs {
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub args: Vec<String>,
}
impl Manual for Cowfs {
    const SECTION: Section = Section::Files;
    const NEEDS: &'static str = "Read access for info/list; root (sudo) for snapshot/subvol/gc.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("cowfs info /", "show root volume UUID, epoch and format"),
        (
            "sudo cowfs snapshot create / before-edit",
            "create a CoW snapshot",
        ),
        ("cowfs snapshot list /", "list snapshots on /"),
    ];
    const SEE: &'static [&'static str] = &["mount", "findmnt", "df"];
}

/// inspect and control local PID 1 init services
///
/// Communicates with `/run/init/control.sock` (or `/run/user/<uid>/manager.sock` with `--user`)
/// authenticated via `SO_PEERCRED`. Ordinary users may inspect unit state (`list`, `status`,
/// `logs`); mutating commands (`start`, `stop`, `restart`, `poweroff`, `reboot`) require root.
#[derive(Parser, Debug)]
#[command(
    name = "service",
    override_usage = "service [--user] list\n       service [--user] status|start|stop|restart|logs UNIT\n       service poweroff|reboot"
)]
pub struct Service {
    /// talk to the per-user service manager instead of system PID 1
    #[arg(long = "user")]
    pub user: bool,
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub args: Vec<String>,
}
impl Manual for Service {
    const SECTION: Section = Section::Terminal;
    const NEEDS: &'static str = "Public for list/status; root (sudo) for system control.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("service list", "list system units and their state"),
        ("service status multi-user.target", "inspect a unit"),
        ("service --user list", "list per-user desktop units"),
    ];
    const SEE: &'static [&'static str] = &["ps", "supervise", "kill"];
}

/// inspect netd status, resolve DNS and configure outbound network egress
///
/// Communicates with `netd` over `/run/netd.sock` authenticated via `SO_PEERCRED`. Offline
/// instances fail closed with `ENETUNREACH` until a network backend is attached.
#[derive(Parser, Debug)]
#[command(
    name = "netctl",
    override_usage = "netctl status\n       netctl resolve HOST\n       netctl policy|attach|detach ..."
)]
pub struct Netctl {
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub args: Vec<String>,
}
impl Manual for Netctl {
    const SECTION: Section = Section::Terminal;
    const NEEDS: &'static str = "Public for status/resolve; root (sudo) for policy changes.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("netctl status", "show active netd state and policy"),
        ("netctl resolve example.com", "resolve a hostname via netd"),
    ];
    const SEE: &'static [&'static str] = &["tunctl", "service"];
}

/// inspect and manage /dev/net/tun virtual network interfaces
///
/// Manages L3 TUN and L2 TAP interfaces exposed through `/dev/net/tun` (`TUNSETIFF`,
/// `TUNGETIFF`, packet framing, and non-blocking I/O).
#[derive(Parser, Debug)]
#[command(name = "tunctl", override_usage = "tunctl info\n       tunctl ...")]
pub struct Tunctl {
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub args: Vec<String>,
}
impl Manual for Tunctl {
    const SECTION: Section = Section::Terminal;
    const NEEDS: &'static str = "Read/write access on /dev/net/tun (or root for interface setup).";
    const EXAMPLES: &'static [(&'static str, &'static str)] =
        &[("tunctl info", "show /dev/net/tun capabilities and queues")];
    const SEE: &'static [&'static str] = &["netctl", "service"];
}
