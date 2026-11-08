//! Accounts: whoami, id, groups, users, login, su, sudo, exit, logout, passwd, useradd, usermod,
//! userdel, groupadd, groupmod and groupdel.

use clap::{Parser, ValueHint};

use super::{Manual, Section};

/// print your account name
///
/// Prints the account this session acts as: guest when signed out.
#[derive(Parser, Debug)]
#[command(name = "whoami")]
pub struct Whoami {}
impl Manual for Whoami {
    const SECTION: Section = Section::Accounts;
    const SEE: &'static [&'static str] = &["id"];
}

/// print uid, gid and groups
///
/// Prints the uid, primary group and every group of you, or USER.
#[derive(Parser, Debug)]
#[command(name = "id")]
pub struct Id {
    /// print only the user ID
    #[arg(short = 'u', long = "user", conflicts_with_all = ["group_only", "groups_only"])]
    pub user_only: bool,
    /// print only the primary group ID
    #[arg(short = 'g', long = "group", conflicts_with = "groups_only")]
    pub group_only: bool,
    /// print all group IDs
    #[arg(short = 'G', long = "groups")]
    pub groups_only: bool,
    /// print names instead of numeric IDs (with -u, -g or -G)
    #[arg(short = 'n', long = "name")]
    pub names: bool,
    /// print real IDs (this runtime has one credential set)
    #[arg(short = 'r', long = "real")]
    pub real: bool,
    #[arg(value_name = "USER")]
    pub user: Option<String>,
}
impl Manual for Id {
    const SECTION: Section = Section::Accounts;
    const EXAMPLES: &'static [(&'static str, &'static str)] =
        &[("id", "yourself"), ("id guest", "who is signed out")];
    const SEE: &'static [&'static str] = &["groups", "whoami"];
}

/// print group names
///
/// Prints the groups of you, or USER.
#[derive(Parser, Debug)]
#[command(name = "groups")]
pub struct Groups {
    #[arg(value_name = "USER")]
    pub user: Option<String>,
}
impl Manual for Groups {
    const SECTION: Section = Section::Accounts;
    const SEE: &'static [&'static str] = &["id"];
}

/// list accounts (root)
///
/// Lists the accounts, their uids, homes, and whether they are locked.
#[derive(Parser, Debug)]
#[command(name = "users")]
pub struct Users {}
impl Manual for Users {
    const SECTION: Section = Section::Accounts;
    const NEEDS: &'static str = "root.";
    const SEE: &'static [&'static str] = &["useradd"];
}

/// sign in
///
/// Signs in through a dialog, and enters the account's home. The username (root) can be changed
/// in the dialog. Sessions last 8 hours; passwords never enter the history.
#[derive(Parser, Debug)]
#[command(name = "login")]
pub struct Login {
    #[arg(value_name = "USER")]
    pub user: Option<String>,
}
impl Manual for Login {
    const SECTION: Section = Section::Accounts;
    const SEE: &'static [&'static str] = &["su", "exit", "useradd"];
}

/// switch account
///
/// Switches this browser to USER (root). - also enters its home. Others give the account's
/// password; root switches to any enabled account without one. exit returns to guest, not to the
/// account before.
#[derive(Parser, Debug)]
#[command(name = "su", override_usage = "su [-] [USER]")]
pub struct Su {
    #[arg(value_name = "USER", num_args = 0..=2)]
    pub operands: Vec<String>,
}
impl Manual for Su {
    const SECTION: Section = Section::Accounts;
    const SEE: &'static [&'static str] = &["login", "sudo", "exit"];
}

/// run a command as root
///
/// Runs a file or account command as root, after you verify your own password, which then holds
/// for 5 minutes; other commands stay yours. Members of wheel only; guest cannot.
///
/// sudo -u USER switches to USER and enters its home (exit returns to guest); -k forgets the
/// verification. Use su root before open, vim or upload as root.
#[derive(Parser, Debug)]
#[command(
    name = "sudo",
    override_usage = "sudo COMMAND...\n       sudo -u USER\n       sudo -k"
)]
pub struct Sudo {
    /// switch to USER
    #[arg(short = 'u', value_name = "USER", conflicts_with_all = ["forget", "command"])]
    pub user: Option<String>,
    /// forget the verification
    #[arg(short = 'k', conflicts_with = "command")]
    pub forget: bool,
    #[arg(value_name = "COMMAND", trailing_var_arg = true)]
    pub command: Vec<String>,
}
impl Manual for Sudo {
    const SECTION: Section = Section::Accounts;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("sudo chown alice:team /shared", "as root"),
        ("sudo -k", "forget"),
    ];
    const SEE: &'static [&'static str] = &["su", "passwd"];
}

/// sign out
///
/// Ends this session, closes the preview, and returns to guest at /; also after su and sudo -u,
/// as there is no account stack.
#[derive(Parser, Debug)]
#[command(name = "exit")]
pub struct Exit {}
impl Manual for Exit {
    const SECTION: Section = Section::Accounts;
    const SEE: &'static [&'static str] = &["logout", "login"];
}

/// sign out
///
/// Ends this session and returns to guest, who is signed out, at /.
#[derive(Parser, Debug)]
#[command(name = "logout")]
pub struct Logout {}
impl Manual for Logout {
    const SECTION: Section = Section::Accounts;
    const SEE: &'static [&'static str] = &["exit", "login"];
}

/// change a password
///
/// Changes a password through a dialog. You give your current password and change only your own;
/// root, or sudo passwd, may reset another account's. Old sessions end; your own change keeps
/// this browser signed in. guest has no password: it is who is signed out.
#[derive(Parser, Debug)]
#[command(name = "passwd")]
pub struct Passwd {
    /// allow a password shorter than 12 characters (never an empty one); at most 512 bytes
    #[arg(long = "force")]
    pub force: bool,
    #[arg(value_name = "USER")]
    pub user: Option<String>,
}
impl Manual for Passwd {
    const SECTION: Section = Section::Accounts;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("passwd", "your own"),
        ("sudo passwd alice", "reset another"),
    ];
    const SEE: &'static [&'static str] = &["useradd", "su"];
}

/// make an account
///
/// Signed out, useradd NAME makes an account of your own: a dialog asks for its password, and
/// you are signed in. Its home is /guest/NAME, which -m makes, mode 700, so that only you may
/// enter it; /guest itself is shared and sticky (1777), so anyone may put files there and only
/// their owners remove them. The account has a group of its own and is in group guest. Other
/// options need sudo. Guests may make up to 1000 accounts, a few a minute from one address.
///
/// Root makes any account: -m makes its home (/home/NAME, or -d HOME), mode 700; without -g, a
/// group of the same name is its primary group; -G adds others. Set its password with passwd
/// NAME.
///
/// Names start with a lowercase letter, with up to 32 lowercase letters, digits, underscores or
/// hyphens; guest is taken.
#[derive(Parser, Debug)]
#[command(
    name = "useradd",
    override_usage = "useradd [-m|-M] [--short-password] NAME              (signed out)\n       useradd [-m|-M] [-d HOME] [-g GROUP] [-G G1,G2] NAME   (root)"
)]
pub struct Useradd {
    /// signed out: allow a password shorter than 12 characters (never an empty one)
    #[arg(long = "short-password")]
    pub short_password: bool,
    /// make the home
    #[arg(short = 'm', long = "create-home", overrides_with = "no_create_home")]
    pub create_home: bool,
    /// make no home (the default)
    #[arg(short = 'M', long = "no-create-home", overrides_with = "create_home")]
    pub no_create_home: bool,
    /// its home
    #[arg(value_hint = ValueHint::DirPath, short = 'd', long = "home-dir", value_name = "HOME")]
    pub home: Option<String>,
    /// its primary group
    #[arg(short = 'g', long = "gid", value_name = "GROUP")]
    pub group: Option<String>,
    /// other groups
    #[arg(short = 'G', long = "groups", value_name = "G1,G2")]
    pub groups: Option<String>,
    #[arg(value_name = "NAME")]
    pub name: String,
}
impl Manual for Useradd {
    const SECTION: Section = Section::Accounts;
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        (
            "useradd -m ada",
            "signed out: an account of your own, with a home",
        ),
        ("sudo useradd -m -G research alice", "root: another account"),
    ];
    const SEE: &'static [&'static str] = &["passwd", "usermod", "userdel"];
}

/// change an account (root)
///
/// -G replaces the other groups, -aG adds to them; -g changes the primary group (not files'). -d
/// changes the home, -m also moves it, to a path not taken. -l renames the account, keeping its
/// uid and files. -L locks it and ends its sessions; -U unlocks it. guest cannot be changed.
#[derive(Parser, Debug)]
#[command(name = "usermod")]
pub struct Usermod {
    /// add to the groups -G names
    #[arg(short = 'a', long = "append", requires = "groups")]
    pub append: bool,
    /// set the other groups
    #[arg(short = 'G', long = "groups", value_name = "G1,G2")]
    pub groups: Option<String>,
    /// primary group
    #[arg(short = 'g', long = "gid", value_name = "GROUP")]
    pub group: Option<String>,
    /// home
    #[arg(value_hint = ValueHint::DirPath, short = 'd', long = "home", value_name = "HOME")]
    pub home: Option<String>,
    /// move the home there too
    #[arg(short = 'm', long = "move-home", requires = "home")]
    pub move_home: bool,
    /// rename
    #[arg(short = 'l', long = "login", value_name = "NEW")]
    pub rename: Option<String>,
    /// lock
    #[arg(short = 'L', long = "lock", conflicts_with = "unlock")]
    pub lock: bool,
    /// unlock
    #[arg(short = 'U', long = "unlock")]
    pub unlock: bool,
    #[arg(value_name = "USER")]
    pub user: String,
}
impl Manual for Usermod {
    const SECTION: Section = Section::Accounts;
    const NEEDS: &'static str = "root.";
    const EXAMPLES: &'static [(&'static str, &'static str)] = &[
        ("usermod -aG wheel alice", "may sudo"),
        ("usermod -d /homes/alice -m alice", "move a home"),
        ("usermod -L alice", "lock"),
    ];
    const SEE: &'static [&'static str] = &["useradd", "userdel"];
}

/// delete an account
///
/// Deletes the account and ends its sessions; -r also removes its home. Its files keep its uid,
/// and root may give them to another. root and guest cannot be deleted.
///
/// Root deletes any account. An account in group guest, as useradd makes them for those signed
/// out, deletes itself: userdel NAME, signed in as NAME; a dialog asks for its password, and you
/// are signed out.
#[derive(Parser, Debug)]
#[command(name = "userdel")]
pub struct Userdel {
    /// remove the home too
    #[arg(short = 'r', long = "remove")]
    pub remove: bool,
    #[arg(value_name = "USER")]
    pub user: String,
}
impl Manual for Userdel {
    const SECTION: Section = Section::Accounts;
    const NEEDS: &'static str = "root; or being the account, in group guest.";
    const SEE: &'static [&'static str] = &["useradd"];
}

/// make a group (root)
///
/// Makes a group; usermod -aG GROUP USER adds members.
#[derive(Parser, Debug)]
#[command(name = "groupadd")]
pub struct Groupadd {
    #[arg(value_name = "GROUP")]
    pub group: String,
}
impl Manual for Groupadd {
    const SECTION: Section = Section::Accounts;
    const NEEDS: &'static str = "root.";
    const SEE: &'static [&'static str] = &["groupmod", "groupdel"];
}

/// rename a group (root)
///
/// Renames the group OLD, by its name (never its number, as on Linux), keeping its gid, members
/// and files. root, wheel and guest cannot be renamed.
#[derive(Parser, Debug)]
#[command(name = "groupmod")]
pub struct Groupmod {
    /// its new name
    #[arg(short = 'n', long = "new-name", value_name = "NEW", required = true)]
    pub new: String,
    #[arg(value_name = "OLD")]
    pub old: String,
}
impl Manual for Groupmod {
    const SECTION: Section = Section::Accounts;
    const NEEDS: &'static str = "root.";
    const SEE: &'static [&'static str] = &["groupadd"];
}

/// delete a group (root)
///
/// Deletes the group GROUP, by its name, and takes it from accounts' other groups. A group still
/// some account's primary group stays. Files keep its gid. root, wheel and guest cannot be
/// deleted.
#[derive(Parser, Debug)]
#[command(name = "groupdel")]
pub struct Groupdel {
    #[arg(value_name = "GROUP")]
    pub group: String,
}
impl Manual for Groupdel {
    const SECTION: Section = Section::Accounts;
    const NEEDS: &'static str = "root.";
    const SEE: &'static [&'static str] = &["groupadd"];
}
