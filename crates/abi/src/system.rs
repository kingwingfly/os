//! The immutable-generation device. All requests use the ordinary ioctl ABI.
//! Public generation identifiers select bytes; root credentials authorize mutations.
pub const DEVICE: &str = "/dev/system";
pub const CONTROL: u32 = 0x4f530001;
