//! `tunctl` — Phase 10b (`#87`) WASI utility for `/dev/net/tun` inspection, L3 ICMP/UDP echo &
//! probes, anti-spoofing/cross-tenant diagnostics, and MTU/queue testing.

use os_posix::tun::{
    TunDevice, build_icmp_echo_reply, build_icmp_echo_request, build_udp_ipv4_packet,
    parse_icmp_echo, parse_udp_ipv4_packet, tun_errno,
};
use serde_json::json;
use std::io::Write;
use std::net::Ipv4Addr;

fn usage() -> &'static str {
    "Usage:\n  \
       tunctl info [--ifname <NAME>] [--mtu <N>] [--network <NET>] [--json]\n  \
       tunctl probe --dst <IP> [--proto icmp|udp] [--port <N>] [--payload <STR>] [--timeout-ms <N>] [--ifname <NAME>] [--network <NET>] [--json]\n  \
       tunctl echo [--count <N>] [--timeout-ms <N>] [--ready-file <PATH>] [--ifname <NAME>] [--network <NET>] [--json]\n  \
       tunctl spoof --src <FORGED_IP> --dst <DST_IP> [--payload <STR>] [--ifname <NAME>] [--network <NET>] [--json]\n  \
       tunctl send --dst <DST_IP> [--src <IP>] [--payload <STR>] [--size <N>] [--count <N>] [--nonblock] [--ifname <NAME>] [--network <NET>] [--json]\n  \
       tunctl hold [--duration-ms <N>] [--ready-file <PATH>] [--ifname <NAME>] [--network <NET>]\n"
}

fn fail_io(op: &str, err: &std::io::Error) -> i32 {
    if let Some(e) = tun_errno(err) {
        eprintln!("tunctl {op}: {e:?}: {err}");
    } else {
        eprintln!("tunctl {op}: {err}");
    }
    1
}

fn open_and_attach(
    ifname: &str,
    mtu: Option<u16>,
    network: Option<&str>,
) -> Result<TunDevice, i32> {
    let tun = TunDevice::open().map_err(|e| fail_io("open /dev/net/tun", &e))?;
    tun.set_iff(ifname, mtu, network)
        .map_err(|e| fail_io("TUNSETIFF", &e))?;
    Ok(tun)
}

pub fn run(args: &[String]) -> i32 {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print!("{}", usage());
        return 0;
    }
    match args[0].as_str() {
        "info" => cmd_info(&args[1..]),
        "probe" => cmd_probe(&args[1..]),
        "echo" => cmd_echo(&args[1..]),
        "spoof" => cmd_spoof(&args[1..]),
        "send" => cmd_send(&args[1..]),
        "hold" => cmd_hold(&args[1..]),
        other => {
            eprintln!("tunctl: unknown subcommand '{other}'\n{}", usage());
            2
        }
    }
}

fn cmd_info(args: &[String]) -> i32 {
    let mut ifname = String::new();
    let mut mtu: Option<u16> = None;
    let mut network: Option<String> = None;
    let mut as_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ifname" => {
                i += 1;
                ifname = args.get(i).cloned().unwrap_or_default();
            }
            "--mtu" => {
                i += 1;
                mtu = args.get(i).and_then(|s| s.parse().ok());
            }
            "--network" => {
                i += 1;
                network = args.get(i).cloned();
            }
            "--json" => as_json = true,
            other => {
                eprintln!("tunctl info: unknown arg '{other}'");
                return 2;
            }
        }
        i += 1;
    }
    let tun = match open_and_attach(&ifname, mtu, network.as_deref()) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let info = match tun.info() {
        Ok(i) => i,
        Err(e) => return fail_io("TUN_IOC_INFO", &e),
    };
    let stats = match tun.stats() {
        Ok(s) => s,
        Err(e) => return fail_io("TUN_IOC_STATS", &e),
    };
    if as_json {
        println!("{}", json!({ "info": info, "stats": stats }));
    } else {
        println!(
            "{}: ip={}/{} gw={} cidr={} mtu={} tenant={} net={} lease={}",
            info.name,
            info.ip,
            info.prefix_len,
            info.gateway,
            info.cidr,
            info.mtu,
            info.tenant,
            info.network,
            info.lease_id
        );
    }
    0
}

fn cmd_probe(args: &[String]) -> i32 {
    let mut dst_str: Option<String> = None;
    let mut proto = "icmp".to_string();
    let mut port: u16 = 5000;
    let mut payload = "hello-overlay".to_string();
    let mut timeout_ms: u64 = 5000;
    let mut ifname = String::new();
    let mut network: Option<String> = None;
    let mut as_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dst" => {
                i += 1;
                dst_str = args.get(i).cloned();
            }
            "--proto" => {
                i += 1;
                proto = args.get(i).cloned().unwrap_or_else(|| "icmp".into());
            }
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(5000);
            }
            "--payload" => {
                i += 1;
                payload = args.get(i).cloned().unwrap_or_default();
            }
            "--timeout-ms" => {
                i += 1;
                timeout_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(5000);
            }
            "--ifname" => {
                i += 1;
                ifname = args.get(i).cloned().unwrap_or_default();
            }
            "--network" => {
                i += 1;
                network = args.get(i).cloned();
            }
            "--json" => as_json = true,
            other => {
                eprintln!("tunctl probe: unknown arg '{other}'");
                return 2;
            }
        }
        i += 1;
    }
    let Some(dst_ip) = dst_str.as_deref().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
        eprintln!("tunctl probe: valid --dst <IPV4> required");
        return 2;
    };
    let tun = match open_and_attach(&ifname, None, network.as_deref()) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let info = match tun.info() {
        Ok(i) => i,
        Err(e) => return fail_io("TUN_IOC_INFO", &e),
    };
    let src_ip: Ipv4Addr = match info.ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("tunctl probe: invalid local IP '{}'", info.ip);
            return 1;
        }
    };

    let pkt = if proto == "udp" {
        build_udp_ipv4_packet(src_ip, dst_ip, 40000, port, payload.as_bytes())
    } else {
        build_icmp_echo_request(src_ip, dst_ip, 0x4242, 1, payload.as_bytes())
    };
    let sent = match tun.write_packet(&pkt) {
        Ok(n) => n,
        Err(e) => return fail_io("write", &e),
    };

    let ready = match tun.poll_readable(timeout_ms) {
        Ok(r) => r,
        Err(e) => return fail_io("poll", &e),
    };
    if !ready {
        eprintln!("tunctl probe: timed out waiting for reply from {dst_ip}");
        return 1;
    }
    let mut rx_buf = vec![0u8; 2048];
    let n = match tun.read_packet(&mut rx_buf) {
        Ok(n) => n,
        Err(e) => return fail_io("read", &e),
    };
    rx_buf.truncate(n);
    let stats = tun.stats().unwrap_or_default();

    let (reply_src, reply_payload) = if proto == "udp" {
        match parse_udp_ipv4_packet(&rx_buf) {
            Some(u) => (
                u.src.to_string(),
                String::from_utf8_lossy(&u.payload).into_owned(),
            ),
            None => {
                eprintln!("tunctl probe: received non-UDP packet ({n} bytes)");
                return 1;
            }
        }
    } else {
        match parse_icmp_echo(&rx_buf) {
            Some(ic) if ic.icmp_type == 0 => (
                ic.src.to_string(),
                String::from_utf8_lossy(&ic.payload).into_owned(),
            ),
            _ => {
                eprintln!("tunctl probe: received non-ICMP-reply packet ({n} bytes)");
                return 1;
            }
        }
    };

    if as_json {
        println!(
            "{}",
            json!({
                "info": info,
                "sent_bytes": sent,
                "reply_bytes": n,
                "reply_src": reply_src,
                "reply_payload": reply_payload,
                "stats": stats,
            })
        );
    } else {
        println!("reply from {reply_src}: bytes={n} payload={reply_payload}");
    }
    0
}

fn cmd_echo(args: &[String]) -> i32 {
    let mut count: u32 = 1;
    let mut timeout_ms: u64 = 10_000;
    let mut ready_file: Option<String> = None;
    let mut ifname = String::new();
    let mut network: Option<String> = None;
    let mut as_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--count" => {
                i += 1;
                count = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--timeout-ms" => {
                i += 1;
                timeout_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(10_000);
            }
            "--ready-file" => {
                i += 1;
                ready_file = args.get(i).cloned();
            }
            "--ifname" => {
                i += 1;
                ifname = args.get(i).cloned().unwrap_or_default();
            }
            "--network" => {
                i += 1;
                network = args.get(i).cloned();
            }
            "--json" => as_json = true,
            other => {
                eprintln!("tunctl echo: unknown arg '{other}'");
                return 2;
            }
        }
        i += 1;
    }
    let tun = match open_and_attach(&ifname, None, network.as_deref()) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let info = match tun.info() {
        Ok(i) => i,
        Err(e) => return fail_io("TUN_IOC_INFO", &e),
    };
    let local_ip: Ipv4Addr = match info.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return 1,
    };
    let info_json = serde_json::to_string(&info).unwrap_or_default();
    if let Some(ref rf) = ready_file {
        let _ = std::fs::write(rf, info_json.as_bytes());
    }
    println!("READY {info_json}");
    let _ = std::io::stdout().flush();

    let mut echoed = 0u32;
    let mut buf = vec![0u8; 2048];
    while echoed < count {
        match tun.poll_readable(timeout_ms) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => return fail_io("poll", &e),
        }
        let n = match tun.read_packet(&mut buf) {
            Ok(n) => n,
            Err(e) => return fail_io("read", &e),
        };
        let pkt = &buf[..n];
        if let Some(ic) = parse_icmp_echo(pkt)
            && ic.icmp_type == 8
        {
            let reply = build_icmp_echo_reply(local_ip, ic.src, ic.id, ic.seq, &ic.payload);
            if let Err(e) = tun.write_packet(&reply) {
                return fail_io("write icmp reply", &e);
            }
            echoed += 1;
        } else if let Some(u) = parse_udp_ipv4_packet(pkt) {
            let reply = build_udp_ipv4_packet(local_ip, u.src, u.dst_port, u.src_port, &u.payload);
            if let Err(e) = tun.write_packet(&reply) {
                return fail_io("write udp reply", &e);
            }
            echoed += 1;
        }
    }
    let stats = tun.stats().unwrap_or_default();
    if as_json {
        println!(
            "{}",
            json!({ "info": info, "echoed": echoed, "stats": stats })
        );
    }
    if echoed == count { 0 } else { 1 }
}

fn cmd_spoof(args: &[String]) -> i32 {
    let mut src_str: Option<String> = None;
    let mut dst_str: Option<String> = None;
    let mut payload = "spoof-test".to_string();
    let mut ifname = String::new();
    let mut network: Option<String> = None;
    let mut as_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--src" => {
                i += 1;
                src_str = args.get(i).cloned();
            }
            "--dst" => {
                i += 1;
                dst_str = args.get(i).cloned();
            }
            "--payload" => {
                i += 1;
                payload = args.get(i).cloned().unwrap_or_default();
            }
            "--ifname" => {
                i += 1;
                ifname = args.get(i).cloned().unwrap_or_default();
            }
            "--network" => {
                i += 1;
                network = args.get(i).cloned();
            }
            "--json" => as_json = true,
            other => {
                eprintln!("tunctl spoof: unknown arg '{other}'");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(src_ip), Some(dst_ip)) = (
        src_str.as_deref().and_then(|s| s.parse::<Ipv4Addr>().ok()),
        dst_str.as_deref().and_then(|s| s.parse::<Ipv4Addr>().ok()),
    ) else {
        eprintln!("tunctl spoof: --src <IPV4> and --dst <IPV4> required");
        return 2;
    };
    let tun = match open_and_attach(&ifname, None, network.as_deref()) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let info = match tun.info() {
        Ok(i) => i,
        Err(e) => return fail_io("TUN_IOC_INFO", &e),
    };
    let pkt = build_icmp_echo_request(src_ip, dst_ip, 0x1111, 1, payload.as_bytes());
    let (write_ok, write_errno) = match tun.write_packet(&pkt) {
        Ok(_) => (true, None),
        Err(e) => (false, tun_errno(&e).map(|en| format!("{en:?}"))),
    };
    let stats = tun.stats().unwrap_or_default();
    if as_json {
        println!(
            "{}",
            json!({
                "info": info,
                "write_ok": write_ok,
                "write_errno": write_errno,
                "stats": stats,
            })
        );
    } else {
        println!(
            "spoof: write_ok={write_ok} dropped_spoofed_src={} dropped_cross_tenant={}",
            stats.tx_dropped_spoofed_src, stats.tx_dropped_cross_tenant
        );
    }
    0
}

fn cmd_send(args: &[String]) -> i32 {
    let mut dst_str: Option<String> = None;
    let mut src_override: Option<String> = None;
    let mut payload = "overlay-data".to_string();
    let mut size: Option<usize> = None;
    let mut count: u32 = 1;
    let mut nonblock = false;
    let mut ifname = String::new();
    let mut network: Option<String> = None;
    let mut as_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dst" => {
                i += 1;
                dst_str = args.get(i).cloned();
            }
            "--src" => {
                i += 1;
                src_override = args.get(i).cloned();
            }
            "--payload" => {
                i += 1;
                payload = args.get(i).cloned().unwrap_or_default();
            }
            "--size" => {
                i += 1;
                size = args.get(i).and_then(|s| s.parse().ok());
            }
            "--count" => {
                i += 1;
                count = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--nonblock" => nonblock = true,
            "--ifname" => {
                i += 1;
                ifname = args.get(i).cloned().unwrap_or_default();
            }
            "--network" => {
                i += 1;
                network = args.get(i).cloned();
            }
            "--json" => as_json = true,
            other => {
                eprintln!("tunctl send: unknown arg '{other}'");
                return 2;
            }
        }
        i += 1;
    }
    let Some(dst_ip) = dst_str.as_deref().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
        eprintln!("tunctl send: valid --dst <IPV4> required");
        return 2;
    };
    let tun = match open_and_attach(&ifname, None, network.as_deref()) {
        Ok(t) => t,
        Err(c) => return c,
    };
    if nonblock {
        let _ = tun.set_nonblocking(true);
    }
    let info = match tun.info() {
        Ok(i) => i,
        Err(e) => return fail_io("TUN_IOC_INFO", &e),
    };
    let src_ip: Ipv4Addr = src_override
        .as_deref()
        .and_then(|s| s.parse().ok())
        .or_else(|| info.ip.parse().ok())
        .unwrap_or(Ipv4Addr::new(10, 64, 0, 2));

    let body: Vec<u8> = if let Some(sz) = size {
        vec![b'X'; sz.saturating_sub(28)]
    } else {
        payload.into_bytes()
    };
    let pkt = build_icmp_echo_request(src_ip, dst_ip, 0x2222, 1, &body);
    let mut sent = 0u32;
    let mut errors: Vec<String> = Vec::new();
    for _ in 0..count {
        match tun.write_packet(&pkt) {
            Ok(_) => sent += 1,
            Err(e) => {
                let name = tun_errno(&e)
                    .map(|en| format!("{en:?}"))
                    .unwrap_or_else(|| e.to_string());
                errors.push(name);
            }
        }
    }
    let stats = tun.stats().unwrap_or_default();
    if as_json {
        println!(
            "{}",
            json!({
                "info": info,
                "sent": sent,
                "errors": errors,
                "stats": stats,
            })
        );
    } else {
        println!("sent={sent} errors={errors:?}");
    }
    0
}

fn cmd_hold(args: &[String]) -> i32 {
    let mut duration_ms: u64 = 30_000;
    let mut ready_file: Option<String> = None;
    let mut ifname = String::new();
    let mut network: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--duration-ms" => {
                i += 1;
                duration_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(30_000);
            }
            "--ready-file" => {
                i += 1;
                ready_file = args.get(i).cloned();
            }
            "--ifname" => {
                i += 1;
                ifname = args.get(i).cloned().unwrap_or_default();
            }
            "--network" => {
                i += 1;
                network = args.get(i).cloned();
            }
            _ => {}
        }
        i += 1;
    }
    let tun = match open_and_attach(&ifname, None, network.as_deref()) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let info = match tun.info() {
        Ok(i) => i,
        Err(e) => return fail_io("TUN_IOC_INFO", &e),
    };
    let info_json = serde_json::to_string(&info).unwrap_or_default();
    if let Some(ref rf) = ready_file {
        let _ = std::fs::write(rf, info_json.as_bytes());
    }
    println!("READY {info_json}");
    let _ = std::io::stdout().flush();
    // Wait on poll_oneoff until duration elapses or killed.
    let _ = tun.poll_readable(duration_ms);
    0
}
