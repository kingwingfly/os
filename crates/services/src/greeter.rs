//! Root-owned modal greeter and lock screen policy (`#61` `L5b`, Contract v2 §2.9).
use abi::{Errno, gui::*};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GreeterAction {
    Help(String),
    Run(GreeterConfig),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GreeterConfig {
    pub role: SurfaceRole,
    pub component: String,
    pub title: String,
}

pub const USAGE: &str = "Usage: greeter [--lock]";

impl GreeterConfig {
    pub fn parse_args(args: &[String]) -> Result<GreeterAction, Errno> {
        match args {
            [] => Ok(GreeterAction::Run(Self {
                role: SurfaceRole::Greeter,
                component: "greeter".into(),
                title: "Sign in".into(),
            })),
            [flag] if flag == "--help" || flag == "-h" => Ok(GreeterAction::Help(USAGE.into())),
            [flag] if flag == "--lock" => Ok(GreeterAction::Run(Self {
                role: SurfaceRole::Lock,
                component: "lock".into(),
                title: "Locked".into(),
            })),
            _ => Err(Errno::EINVAL),
        }
    }

    pub fn surface_spec(&self) -> SurfaceSpec {
        SurfaceSpec {
            role: self.role,
            kind: SurfaceKind::Host {
                component: self.component.clone(),
            },
            title: self.title.clone(),
            rect: Rect {
                x: 0,
                y: 0,
                width: 1024,
                height: 720,
            },
            min_size: Size {
                width: 1,
                height: 1,
            },
            max_size: None,
            resizable: false,
            app_id: Some(self.component.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_greeter_and_lock_modes_and_builds_host_spec() {
        let GreeterAction::Run(default_cfg) = GreeterConfig::parse_args(&[]).unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(default_cfg.role, SurfaceRole::Greeter);
        assert!(default_cfg.role.modal());
        assert_eq!(
            default_cfg.surface_spec().kind,
            SurfaceKind::Host {
                component: "greeter".into()
            }
        );

        let GreeterAction::Run(lock_cfg) = GreeterConfig::parse_args(&["--lock".into()]).unwrap()
        else {
            panic!("expected Run");
        };
        assert_eq!(lock_cfg.role, SurfaceRole::Lock);
        assert_eq!(
            lock_cfg.surface_spec().kind,
            SurfaceKind::Host {
                component: "lock".into()
            }
        );

        assert_eq!(
            GreeterConfig::parse_args(&["--bogus".into()]),
            Err(Errno::EINVAL)
        );
    }
}
