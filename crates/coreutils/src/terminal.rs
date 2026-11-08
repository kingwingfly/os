//! tty/stty are user-space programs over the client kernel's ioctl calls.
use serde_json::{Value, json};
use std::ffi::OsString;
use os_core::cli::{self, terminal::Stty};

fn ioctl(request: u32, arg: Value) -> Result<Value, String> {
    #[cfg(target_os = "wasi")]
    {
        let calls = json!([{"ioctl": {"fd": 0, "request": request, "arg": arg}}]).to_string();
        // SAFETY: the engine reads this string and writes the returned length to our buffer.
        let len = unsafe { super::sys(calls.as_ptr(), calls.len()) };
        if len > 65536 {
            return Err("invalid ioctl response".into());
        }
        let mut out = vec![0; len];
        unsafe { super::reply(out.as_mut_ptr()) };
        let value: Value = serde_json::from_slice(&out).map_err(|e| e.to_string())?;
        let result = &value["results"][0];
        if let Some(value) = result.get("ok") {
            return Ok(value.clone());
        }
        Err(match result["err"]["errno"].as_str().unwrap_or("EIO") {
            "ENOTTY" => "Inappropriate ioctl for device",
            "EBADF" => "Bad file descriptor",
            "EINVAL" => "Invalid argument",
            "EOPNOTSUPP" => "Operation not supported",
            _ => "Input/output error",
        }
        .into())
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = (request, arg);
        Err("terminal ioctls require the WASI engine".into())
    }
}

pub fn tty(args: impl Iterator<Item = OsString>) -> i32 {
    let args: Vec<_> = args.skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: tty [-s|--silent]\nPrint the terminal attached to standard input.");
        return 0;
    }
    if args
        .iter()
        .any(|a| a != "-s" && a != "--silent" && a != "--quiet")
    {
        eprintln!("tty: invalid option");
        return 2;
    }
    match ioctl(0x80045430, Value::Null) {
        Ok(value) => {
            if args.is_empty() {
                println!("{}", value["name"].as_str().unwrap_or("/dev/tty"));
            }
            0
        }
        Err(_) => {
            if args.is_empty() {
                println!("not a tty");
            }
            1
        }
    }
}

pub fn stty(args: impl Iterator<Item = OsString>) -> i32 {
    let args: Vec<String> = args
        .skip(1)
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{}", cli::help("stty").unwrap_or_default());
        return 0;
    }
    let result = (|| -> Result<(), String> {
        let opts = cli::parse::<Stty>(&args)?;
        let mut modes = ioctl(0x5401, Value::Null)?;
        let mut size = ioctl(0x5413, Value::Null)?;
        if opts.settings.is_empty() || opts.all {
            println!("rows {}; columns {};", size["rows"], size["columns"]);
            let flags: Vec<_> = [
                ("lflag", 8, "echo"),
                ("lflag", 2, "icanon"),
                ("lflag", 1, "isig"),
                ("oflag", 1, "opost"),
                ("oflag", 4, "onlcr"),
            ]
            .iter()
            .map(|(field, bit, name)| {
                format!(
                    "{}{name}",
                    if modes[field].as_u64().unwrap_or(0) & bit != 0 {
                        ""
                    } else {
                        "-"
                    }
                )
            })
            .collect();
            println!(
                "{}; min {}; time {};",
                flags.join(" "),
                modes["cc"][6],
                modes["cc"][5]
            );
        }
        let mut iter = opts.settings.iter();
        let mut changed = false;
        let mut resized = false;
        while let Some(setting) = iter.next() {
            match setting.as_str() {
                "size" => println!("{} {}", size["rows"], size["columns"]),
                "min" | "time" | "rows" | "cols" => {
                    let value: u32 = iter
                        .next()
                        .ok_or_else(|| format!("missing argument to '{setting}'"))?
                        .parse()
                        .map_err(|_| format!("invalid {setting}"))?;
                    if setting == "min" || setting == "time" {
                        if value > 255 {
                            return Err(format!("invalid {setting}"));
                        }
                        modes["cc"][if setting == "min" { 6 } else { 5 }] = value.into();
                        changed = true;
                    } else {
                        if value == 0 || value > 65535 {
                            return Err(format!("invalid {setting}"));
                        }
                        size[if setting == "rows" { "rows" } else { "columns" }] = value.into();
                        resized = true;
                    }
                }
                "sane" | "cooked" => {
                    modes["iflag"] = 256.into();
                    modes["oflag"] = 5.into();
                    modes["lflag"] = 571.into();
                    modes["cc"][6] = 1.into();
                    modes["cc"][5] = 0.into();
                    changed = true;
                }
                "raw" => {
                    modes["iflag"] = 0.into();
                    modes["oflag"] = 0.into();
                    modes["lflag"] = 0.into();
                    modes["cc"][6] = 1.into();
                    modes["cc"][5] = 0.into();
                    changed = true;
                }
                mode => {
                    let (on, name) = mode.strip_prefix('-').map_or((true, mode), |s| (false, s));
                    let (field, bit) = match name {
                        "echo" => ("lflag", 8),
                        "icanon" => ("lflag", 2),
                        "isig" => ("lflag", 1),
                        "opost" => ("oflag", 1),
                        "onlcr" => ("oflag", 4),
                        _ => return Err(format!("invalid argument '{mode}'")),
                    };
                    let flags = modes[field].as_u64().unwrap_or(0);
                    modes[field] = (if on { flags | bit } else { flags & !bit }).into();
                    changed = true;
                }
            }
        }
        if changed {
            ioctl(0x5402, modes)?;
        }
        if resized {
            ioctl(0x5414, size)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("stty: {error}");
            1
        }
    }
}
