use super::{Manual, Section};
use clap::{Parser, Subcommand};

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
