//! Operator policy stays in an ordinary executable; the device enforces authorization.
use abi::{Call, system};
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
    use os_core::cli::{
        self,
        system::{ImageAction, ImageCtl},
    };
    let parsed = cli::parse::<ImageCtl>(args)?;
    let (operation, release) = match parsed.action.unwrap_or(ImageAction::Status) {
        ImageAction::Status => ("status", None),
        ImageAction::Stage { release } => ("stage", Some(release)),
        ImageAction::Activate { release } => ("activate", Some(release)),
        ImageAction::Rollback { release } => ("rollback", Some(release)),
    };
    let writing = operation != "status";
    let opened = call(Call::Open {
        path: system::DEVICE.into(),
        flags: if writing { abi::O_RDWR } else { abi::O_RDONLY },
        mode: 0,
        size: None,
        sha256: None,
        version: None,
    })?;
    let fd = opened["fd"]
        .as_u64()
        .ok_or("device open returned no descriptor")? as u32;
    let ioctl = |arg| {
        call(Call::Ioctl {
            fd: fd.into(),
            request: system::CONTROL,
            arg,
        })
    };
    let result: Result<(), String> = (|| {
        let mut arg = json!({"op":operation});
        if writing {
            arg["id"] = json!(release);
        }
        if matches!(operation, "activate" | "rollback") {
            arg["expected"] = ioctl(json!({"op":"status"}))?["active"].clone();
        }
        let result = ioctl(arg)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
        );
        Ok(())
    })();
    let closed = call(Call::Close { fd: fd.into() });
    result?;
    closed?;
    Ok(())
}
