//! Times, as GNU's tools write and read them: in UTC, the time the kernel keeps (seconds since
//! 1970 and nanoseconds past them), as stat, ls and touch show and take them.

/// Days since 1970 as a year, month and day (Howard Hinnant's days-to-civil).
pub fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// A year, month and day as days since 1970 (its inverse).
pub fn days(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `seconds` and `nsec` as stat shows them: `2026-10-29 12:00:00.123456789 +0000`.
pub fn datetime(seconds: u64, nsec: u32) -> String {
    let (date, time) = parts(seconds);
    format!("{date} {time}.{nsec:09} +0000")
}

/// The date and the time of day, `YYYY-MM-DD` and `HH:MM:SS`.
fn parts(seconds: u64) -> (String, String) {
    let (day, rest) = ((seconds / 86_400) as i64, seconds % 86_400);
    let (year, month, day) = civil(day);
    (
        format!("{year:04}-{month:02}-{day:02}"),
        format!(
            "{:02}:{:02}:{:02}",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60
        ),
    )
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `seconds` as ls -l shows it, as of `now`: the month, day and time for what is less than half a
/// year old (or in the future by less than an hour); the year in place of the time otherwise.
pub fn listed(seconds: u64, now: u64) -> String {
    let (year, month, day) = civil((seconds / 86_400) as i64);
    let recent = seconds + 183 * 86_400 > now && seconds < now + 3600;
    let month = MONTHS[month as usize - 1];
    if recent {
        let rest = seconds % 86_400;
        format!(
            "{month} {day:>2} {:02}:{:02}",
            rest / 3600,
            rest % 3600 / 60
        )
    } else {
        format!("{month} {day:>2}  {year}")
    }
}

/// `seconds` and `nsec` as ls --full-time shows them.
pub fn full(seconds: u64, nsec: u32) -> String {
    datetime(seconds, nsec)
}

/// A date as touch -d takes one: `@SECONDS[.FRACTION]`, `now`, `YYYY-MM-DD`, or that with a time
/// of day, `[T ]HH:MM[:SS[.FRACTION]]`, and an offset from UTC, `Z`, `UTC` or `±HH[:]MM`; UTC
/// unless it says otherwise. As seconds and nanoseconds; `now` for the clock's.
pub fn parse_date(text: &str, now: u64) -> Result<(u64, u32), String> {
    let invalid = || format!("invalid date format {}", crate::io::quote(text));
    let text = text.trim();
    if text == "now" {
        return Ok((now, 0));
    }
    if let Some(seconds) = text.strip_prefix('@') {
        let (whole, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
        let whole: u64 = whole.parse().map_err(|_| invalid())?;
        return Ok((whole, nanos(fraction).ok_or_else(invalid)?));
    }
    // An offset at its end.
    let (text, offset) = if let Some(rest) = text.strip_suffix('Z').or(text.strip_suffix(" UTC")) {
        (rest, 0)
    } else {
        match text.rfind(['+', '-']).filter(|at| *at > 10) {
            Some(at) => {
                let digits: String = text[at + 1..].chars().filter(|c| *c != ':').collect();
                if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                let minutes = digits[..2].parse::<i64>().unwrap_or(0) * 60
                    + digits[2..].parse::<i64>().unwrap_or(0);
                let sign = if &text[at..=at] == "-" { -1 } else { 1 };
                (text[..at].trim_end(), sign * minutes * 60)
            }
            None => (text, 0),
        }
    };
    let (date, time) = text
        .split_once(['T', ' '])
        .map_or((text, ""), |(date, time)| (date, time.trim()));
    let fields: Vec<&str> = date.split('-').collect();
    let [year, month, day] = fields.as_slice() else {
        return Err(invalid());
    };
    let (year, month, day): (i64, u32, u32) = (
        year.parse().map_err(|_| invalid())?,
        month.parse().map_err(|_| invalid())?,
        day.parse().map_err(|_| invalid())?,
    );
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(invalid());
    }
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let clock: Vec<&str> = if clock.is_empty() {
        Vec::new()
    } else {
        clock.split(':').collect()
    };
    if clock.len() == 1 || clock.len() > 3 {
        return Err(invalid());
    }
    let field = |i: usize, most: i64| -> Result<i64, String> {
        let value: i64 = clock
            .get(i)
            .map_or(Ok(0), |v| v.parse())
            .map_err(|_| invalid())?;
        if value > most {
            Err(invalid())
        } else {
            Ok(value)
        }
    };
    let seconds =
        days(year, month, day) * 86_400 + field(0, 23)? * 3600 + field(1, 59)? * 60 + field(2, 60)?
            - offset;
    let nsec = nanos(fraction).ok_or_else(invalid)?;
    u64::try_from(seconds)
        .map(|seconds| (seconds, nsec))
        .map_err(|_| invalid())
}

/// A stamp as touch -t takes one: `[[CC]YY]MMDDhhmm[.ss]`, in UTC; the year of `now` if it has
/// none, and for two digits of it, 1969–2068, as POSIX has them.
pub fn parse_stamp(text: &str, now: u64) -> Result<(u64, u32), String> {
    let invalid = || format!("invalid date format {}", crate::io::quote(text));
    let (digits, seconds) = text.split_once('.').unwrap_or((text, "00"));
    if !digits.bytes().all(|b| b.is_ascii_digit())
        || seconds.len() != 2
        || !seconds.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    let year = match digits.len() {
        8 => civil((now / 86_400) as i64).0,
        10 => {
            let yy: i64 = digits[..2].parse().map_err(|_| invalid())?;
            if yy >= 69 { 1900 + yy } else { 2000 + yy }
        }
        12 => digits[..4].parse().map_err(|_| invalid())?,
        _ => return Err(invalid()),
    };
    let rest = &digits[digits.len() - 8..];
    let number = |range: std::ops::Range<usize>| rest[range].parse::<u32>().unwrap_or(99);
    parse_date(
        &format!(
            "{year:04}-{:02}-{:02} {:02}:{:02}:{seconds}",
            number(0..2),
            number(2..4),
            number(4..6),
            number(6..8)
        ),
        now,
    )
    .map_err(|_| invalid())
}

/// The digits of a fraction of a second as nanoseconds, at most nine of them counted.
fn nanos(fraction: &str) -> Option<u32> {
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits: String = fraction
        .chars()
        .chain("000000000".chars())
        .take(9)
        .collect();
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_read_and_write_as_gnu_s_tools_do() {
        assert_eq!(datetime(0, 5), "1970-01-01 00:00:00.000000005 +0000");
        assert_eq!(days(2026, 10, 29), 20_755);
        assert_eq!(civil(20_755), (2026, 10, 29));
        let now = 1_793_291_641;
        assert_eq!(
            parse_date("@1700000000.25", now),
            Ok((1_700_000_000, 250_000_000))
        );
        assert_eq!(parse_date("2026-10-29", now), Ok((20_755 * 86_400, 0)));
        assert_eq!(
            parse_date("2026-10-29 12:30:05.5Z", now),
            Ok((20_755 * 86_400 + 45_005, 500_000_000))
        );
        assert_eq!(
            parse_date("2026-10-29T12:30+01:00", now),
            Ok((20_755 * 86_400 + 41_400, 0))
        );
        assert!(parse_date("yesterday-ish", now).is_err());
        assert!(parse_date("2026-13-01", now).is_err());
        assert_eq!(
            parse_stamp("202610291230.05", now),
            Ok((20_755 * 86_400 + 45_005, 0))
        );
        assert_eq!(
            parse_stamp("10291230", now).map(|t| t.0 / 86_400),
            Ok(20_755)
        );
        assert_eq!(listed(now, now), "Oct 29 16:34");
        assert_eq!(listed(0, now), "Jan  1  1970");
    }
}
