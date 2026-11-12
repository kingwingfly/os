use abi::{
    Call,
    accelerator::{self, ProviderPolicy},
};
use os_core::cli::{self, system::ProviderCtl};
use serde_json::{Value, json};
fn call(call: Call) -> Result<Value, String> {
    os_posix::batch(&[call])
        .map_err(|e| e.to_string())?
        .results
        .remove(0)
        .into_result()
        .map_err(|e| e.to_string())
}
pub fn run(args: &[String]) -> Result<(), String> {
    let parsed = cli::parse::<ProviderCtl>(args)?;
    let opened = call(Call::Open {
        path: parsed.device,
        flags: abi::O_RDWR,
        mode: 0,
        size: None,
        sha256: None,
        version: None,
    })?;
    let fd = opened["fd"]
        .as_u64()
        .ok_or("device did not return a descriptor")? as u32;
    let ioctl = |request, arg| {
        call(Call::Ioctl {
            fd: fd.into(),
            request,
            arg,
        })
    };
    let result: Result<(), String> = (|| {
        let mut policy: ProviderPolicy =
            serde_json::from_value(ioctl(accelerator::POLICY, json!({}))?)
                .map_err(|e| e.to_string())?;
        let changing = parsed.enabled.is_some()
            || parsed.detached.is_some()
            || parsed.max_active.is_some()
            || parsed.timeout.is_some();
        if let Some(value) = parsed.enabled {
            policy.enabled = value;
        }
        if let Some(value) = parsed.detached {
            policy.detached = value;
        }
        if let Some(value) = parsed.max_active {
            policy.max_active = value;
        }
        if let Some(value) = parsed.timeout {
            policy.max_seconds = value;
        }
        policy.validate().map_err(|e| e.to_string())?;
        let value = if changing {
            ioctl(accelerator::CONFIGURE, json!(policy))?
        } else {
            json!(policy)
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
        );
        Ok(())
    })();
    let closed = call(Call::Close { fd: fd.into() });
    result?;
    closed?;
    Ok(())
}
