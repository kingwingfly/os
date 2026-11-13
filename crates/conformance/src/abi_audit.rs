//! Audited Call variants contain no mount, unmount or chroot operation.
//! An addition/rename must fail compilation until the unsupported probes are
//! reviewed against the new ABI. This is deliberately exhaustive, without `_`.
//! Comments, impl placement and enum ordering do not affect this type check.
use abi::Call;

const _: fn(Call) = |call| match call {
    Call::Getcreds
    | Call::Stat { .. }
    | Call::Lstat { .. }
    | Call::Getdents { .. }
    | Call::Access { .. }
    | Call::Readlink { .. }
    | Call::Mkdir { .. }
    | Call::Mknod { .. }
    | Call::Rmdir { .. }
    | Call::Unlink { .. }
    | Call::Rename { .. }
    | Call::Link { .. }
    | Call::Symlink { .. }
    | Call::Chmod { .. }
    | Call::Chown { .. }
    | Call::Utimens { .. }
    | Call::Statfs { .. }
    | Call::Getxattr { .. }
    | Call::Setxattr { .. }
    | Call::Listxattr { .. }
    | Call::Removexattr { .. }
    | Call::Open { .. }
    | Call::Close { .. }
    | Call::Discard { .. }
    | Call::Fchmod { .. }
    | Call::Pread { .. }
    | Call::Pwrite { .. }
    | Call::Login { .. }
    | Call::Logout
    | Call::Sudo { .. }
    | Call::Passwd { .. }
    | Call::Useradd { .. }
    | Call::Usermod { .. }
    | Call::Userdel { .. }
    | Call::Groupadd { .. }
    | Call::Groupmod { .. }
    | Call::Groupdel { .. }
    | Call::InotifyAddWatch { .. }
    | Call::InotifyRmWatch { .. }
    | Call::ProcInit { .. }
    | Call::Execve { .. }
    | Call::ProcTty { .. }
    | Call::Fork { .. }
    | Call::Exit { .. }
    | Call::Pids { .. }
    | Call::Seats
    | Call::MachineInit { .. }
    | Call::LoginSession { .. }
    | Call::Gone { .. }
    | Call::Getpid
    | Call::Getpgid { .. }
    | Call::Getsid { .. }
    | Call::Setpgid { .. }
    | Call::Setsid
    | Call::ProcSession { .. }
    | Call::Prctl { .. }
    | Call::ProcStopped { .. }
    | Call::Waitpid { .. }
    | Call::ProcPoll { .. }
    | Call::ProcKeep { .. }
    | Call::CgroupCreate { .. }
    | Call::CgroupRemove { .. }
    | Call::CgroupSet { .. }
    | Call::CgroupAttach { .. }
    | Call::CgroupStat { .. }
    | Call::Resource { .. }
    | Call::CgroupList { .. }
    | Call::Kill { .. }
    | Call::Wait { .. }
    | Call::Ioctl { .. } => (),
};
