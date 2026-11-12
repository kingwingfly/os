//! Versioned accelerator control, transported by ioctl on an authorized device descriptor.
//! Resource names are relative to directory handles, never storage keys or credentials.
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
pub const INFO: u32 = 0x5457_0100;
pub const SUBMIT: u32 = 0x5457_0101;
pub const POLL: u32 = 0x5457_0102;
pub const ANSWER: u32 = 0x5457_0103;
pub const CANCEL: u32 = 0x5457_0104;
pub const DETACH: u32 = 0x5457_0105;
pub const ATTACH: u32 = 0x5457_0106;
pub const POLICY: u32 = 0x5457_0107;
pub const CONFIGURE: u32 = 0x5457_0108;
pub const MAX_ACTIVE: usize = 16;
pub const MAX_EVENTS: usize = 128;
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// Durable output is a bounded spool; readers page it without loading it all in memory.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const ARCHIVE: &str = "/dev/archive";
pub const MEDIA: &str = "/dev/media";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPolicy {
    pub version: u32,
    pub revision: u64,
    pub enabled: bool,
    pub detached: bool,
    pub max_active: u32,
    pub max_seconds: u64,
}
impl Default for ProviderPolicy {
    fn default() -> Self {
        Self {
            version: VERSION,
            revision: 0,
            enabled: true,
            detached: true,
            max_active: MAX_ACTIVE as u32,
            max_seconds: 604800,
        }
    }
}
impl ProviderPolicy {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.version != VERSION {
            return Err(crate::Errno::EOPNOTSUPP.into());
        }
        if self.revision >= (1 << 53) - 1
            || self.max_active > MAX_ACTIVE as u32
            || !(1..=604800).contains(&self.max_seconds)
        {
            return Err(crate::Errno::EINVAL.into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Zip,
    Tar,
    Tgz,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Existing {
    Ask,
    Replace,
    Skip,
    Keep,
}

/// One name in an opened directory. `.` names the directory itself. A driver revalidates
/// the handle's inode and the caller's permissions when deriving a remote resource grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathAt {
    pub directory: u32,
    pub name: String,
}
impl PathAt {
    pub fn valid(&self) -> bool {
        !self.name.is_empty()
            && self.name != ".."
            && self.name.len() <= 255
            && !self.name.contains(['/', '\0'])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub source: PathAt,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Create {
        format: Format,
        output: PathAt,
        inputs: Vec<Input>,
        recursive: bool,
        links: bool,
        verbose: bool,
    },
    Extract {
        format: Format,
        source: PathAt,
        destination: PathAt,
        existing: Existing,
        members: Vec<String>,
        verbose: bool,
    },
    List {
        format: Format,
        source: PathAt,
        verbose: bool,
    },
    Faststart {
        file: PathAt,
    },
}
impl Operation {
    pub fn device(&self) -> &'static str {
        match self {
            Self::Faststart { .. } => MEDIA,
            _ => ARCHIVE,
        }
    }
    pub fn resources(&self) -> Vec<&PathAt> {
        match self {
            Self::Create { output, inputs, .. } => std::iter::once(output)
                .chain(inputs.iter().map(|i| &i.source))
                .collect(),
            Self::Extract {
                source,
                destination,
                ..
            } => vec![source, destination],
            Self::List { source, .. } => vec![source],
            Self::Faststart { file } => vec![file],
        }
    }
}

/// A retry key belongs to the submitting credential lineage. Reusing it with different
/// parameters fails, including after completion; it can never repeat a committed write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submit {
    pub version: u32,
    pub request: String,
    pub operation: Operation,
}
impl Submit {
    pub fn validate(&self) -> Result<(), crate::Errno> {
        if self.version != VERSION {
            return Err(crate::Errno::EOPNOTSUPP);
        }
        if self.request.is_empty()
            || self.request.len() > 64
            || !self
                .request
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.operation.resources().iter().any(|r| !r.valid())
        {
            return Err(crate::Errno::EINVAL);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub version: u32,
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    pub version: u32,
    pub id: String,
    pub after: u64,
    pub limit: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    pub version: u32,
    pub id: String,
    /// Sequence of the conflict event. A stale answer cannot decide a later conflict.
    pub sequence: u64,
    pub decisions: std::collections::BTreeMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Output {
        sequence: u64,
        stderr: bool,
        text: String,
    },
    Conflict {
        sequence: u64,
        paths: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Completion {
    pub version: u32,
    pub id: String,
    pub request: String,
    pub state: String,
    pub events: Vec<Event>,
    pub more: bool,
    pub completed: u64,
    pub total: u64,
    pub errors: u64,
    pub status: Option<u8>,
    pub error: Option<crate::Errno>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_versions_ambiguous_resources_and_extra_authority() {
        let mut request = Submit {
            version: VERSION,
            request: "retry-123".into(),
            operation: Operation::List {
                format: Format::Zip,
                source: PathAt {
                    directory: 3,
                    name: "input.zip".into(),
                },
                verbose: false,
            },
        };
        assert!(request.validate().is_ok());
        request.version += 1;
        assert_eq!(request.validate(), Err(crate::Errno::EOPNOTSUPP));
        for name in ["", "..", "../private", "/private", "a/b", "a\0b"] {
            assert!(
                !PathAt {
                    directory: 3,
                    name: name.into()
                }
                .valid()
            );
        }
        let mut value = serde_json::to_value(request).unwrap();
        value["uid"] = 0.into();
        assert!(serde_json::from_value::<Submit>(value).is_err());
    }
}
