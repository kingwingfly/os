//! Storage-byte admission policy, independent of any transport or command.
use abi::Errno;
type Result<T> = std::result::Result<T, abi::Error>;
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct IoLimit {
    pub read: Option<u64>,
    pub write: Option<u64>,
}
impl IoLimit {
    pub fn parse(value: &str) -> Result<Self> {
        if value == "max" {
            return Ok(Self::default());
        }
        let mut result = Self::default();
        let mut seen = 0;
        for part in value.split_whitespace() {
            let (name, value) = part.split_once('=').ok_or(Errno::EINVAL)?;
            let (slot, bit) = match name {
                "rbps" => (&mut result.read, 1),
                "wbps" => (&mut result.write, 2),
                _ => return Err(Errno::EINVAL.into()),
            };
            if seen & bit != 0 {
                return Err(Errno::EINVAL.into());
            }
            seen |= bit;
            *slot = if value == "max" {
                None
            } else {
                if value.is_empty() || !value.bytes().all(|v| v.is_ascii_digit()) {
                    return Err(Errno::EINVAL.into());
                }
                Some(value.parse().map_err(|_| Errno::EINVAL)?)
            };
        }
        if seen == 0 {
            return Err(Errno::EINVAL.into());
        }
        Ok(result)
    }
}
/// Reserve a complete transfer before its first byte. No idle burst credit. The
/// caller commits all ancestor reservations atomically and waits outside its lock.
pub fn io_deadline(now: u64, previous: u64, rate: Option<u64>, bytes: u64) -> Result<u64> {
    if bytes == 0 || rate.is_none() {
        return Ok(now);
    }
    let rate = rate.unwrap();
    if rate == 0 {
        return Err(Errno::EAGAIN.into());
    }
    let duration = (u128::from(bytes) * 1000).div_ceil(u128::from(rate));
    let end = u128::from(previous.max(now)) + duration;
    if end > u128::from(now) + 30_000 {
        return Err(Errno::EAGAIN.into());
    }
    Ok(end as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_pacing_has_no_idle_credit_and_denials_do_not_advance_it() {
        let a = io_deadline(1000, 0, Some(100), 50).unwrap();
        assert_eq!(a, 1500);
        assert_eq!(io_deadline(1000, a, Some(100), 50).unwrap(), 2000);
        assert_eq!(io_deadline(100_000, a, Some(100), 50).unwrap(), 100_500);
        assert!(io_deadline(1000, a, Some(100), 3000).is_err());
        assert!(io_deadline(0, 0, Some(1), u64::MAX).is_err());
        assert!(io_deadline(0, 0, Some(0), 1).is_err());
        assert_eq!(io_deadline(0, 9000, None, u64::MAX).unwrap(), 0);
    }
    #[test]
    fn only_declared_byte_rate_fields_are_accepted() {
        assert_eq!(
            IoLimit::parse("rbps=0 wbps=max").unwrap(),
            IoLimit {
                read: Some(0),
                write: None
            }
        );
        for invalid in [
            "",
            "100",
            "rbps=-1",
            "rbps=+1",
            "rbps=1.0",
            "rbps=1 rbps=2",
            "riops=10",
        ] {
            assert!(IoLimit::parse(invalid).is_err(), "{invalid}");
        }
    }
}
