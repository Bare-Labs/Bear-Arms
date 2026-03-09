use std::net::Ipv4Addr;

use crate::types::NetConnection;

pub fn collect() -> Vec<NetConnection> {
    let mut connections = Vec::new();
    connections.extend(parse_proc_tcp("/proc/net/tcp", "tcp"));
    connections.extend(parse_proc_tcp("/proc/net/tcp6", "tcp6"));
    connections
}

fn parse_proc_tcp(path: &str, protocol: &str) -> Vec<NetConnection> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut connections = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let state = decode_state(fields[3]);

        if protocol == "tcp6" {
            if let (Some((la, lp)), Some((ra, rp))) =
                (parse_addr_v6(fields[1]), parse_addr_v6(fields[2]))
            {
                connections.push(NetConnection {
                    local_addr: la,
                    local_port: lp,
                    remote_addr: ra,
                    remote_port: rp,
                    state,
                    protocol: protocol.to_string(),
                });
            }
        } else if let (Some((la, lp)), Some((ra, rp))) =
            (parse_addr_v4(fields[1]), parse_addr_v4(fields[2]))
        {
            connections.push(NetConnection {
                local_addr: la,
                local_port: lp,
                remote_addr: ra,
                remote_port: rp,
                state,
                protocol: protocol.to_string(),
            });
        }
    }

    connections
}

// Linux stores IPv4 as a little-endian u32 in /proc/net/tcp.
// Reading the hex string directly gives us the LE byte representation.
// to_ne_bytes() on a LE system returns bytes suitable for Ipv4Addr::from().
fn parse_addr_v4(s: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let addr_u32 = u32::from_str_radix(addr_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = Ipv4Addr::from(addr_u32.to_ne_bytes());
    Some((ip.to_string(), port))
}

// IPv6 addresses in /proc/net/tcp6 are 32 hex chars (four LE u32 words).
fn parse_addr_v6(s: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 32 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    let mut bytes = [0u8; 16];
    for (i, chunk) in addr_hex.as_bytes().chunks(8).enumerate() {
        let word_hex = std::str::from_utf8(chunk).ok()?;
        let word = u32::from_str_radix(word_hex, 16).ok()?;
        let word_bytes = word.to_ne_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }

    let ip = std::net::Ipv6Addr::from(bytes);
    // If mapped IPv4, show the v4 form
    let ip_str = match ip.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => ip.to_string(),
    };

    Some((ip_str, port))
}

fn decode_state(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
    .to_string()
}
