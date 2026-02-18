use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use ironshim_rs::crypto::{hmac_sha256, Sha256};

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("ironport-client <addr> index");
        eprintln!("ironport-client <addr> get <name> <out>");
        eprintln!("ironport-client <addr> get-verified <name> <out>");
        return;
    }
    if args.len() == 2 && args[1] == "index" {
        if let Ok(body) = request(&args[0], "/index") {
            println!("{body}");
        }
        return;
    }
    if args.len() == 4 && args[1] == "get" {
        let name = &args[2];
        let out = PathBuf::from(&args[3]);
        if let Ok(body) = request(&args[0], &format!("/file/{name}")) {
            let _ = fs::write(out, body.as_bytes());
        }
        return;
    }
    if args.len() == 4 && args[1] == "get-verified" {
        let name = &args[2];
        let out = PathBuf::from(&args[3]);
        if let Ok(body) = request(&args[0], &format!("/file/{name}")) {
            if let Ok(sig) = request(&args[0], &format!("/file/{name}.sig")) {
                if let Ok(prov) = request(&args[0], &format!("/file/{name}.prov")) {
                    let revoked = load_revoked(Path::new("revoked.keys"));
                    let trusted = load_trusted(Path::new("trusted.keys"));
                    if verify_signature(&sig, body.as_bytes(), &revoked, &trusted)
                        && verify_provenance(&prov, body.as_bytes())
                    {
                        let _ = fs::write(out, body.as_bytes());
                    } else {
                        eprintln!("verification failed");
                    }
                }
            }
        }
        return;
    }
    eprintln!("ironport-client <addr> index");
    eprintln!("ironport-client <addr> get <name> <out>");
    eprintln!("ironport-client <addr> get-verified <name> <out>");
}

fn request(addr: &str, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if let Some((_, body)) = response.split_once("\r\n\r\n") {
        Ok(body.to_string())
    } else {
        Ok(String::new())
    }
}

fn verify_signature(
    sig: &str,
    content: &[u8],
    revoked: &HashSet<String>,
    trusted: &HashMap<String, TrustedKey>,
) -> bool {
    let record = match parse_signature(sig) {
        Some(record) => record,
        None => return false,
    };
    if revoked.contains(&record.key_id) {
        return false;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if record.issued > now || record.expires < now {
        return false;
    }
    if !validate_chain(&record.key_id, trusted, revoked, now) {
        return false;
    }
    let payload = build_signature_payload(content, &record.key_id, &record.prev_id, record.issued, record.expires);
    match record.alg.as_str() {
        "HMAC-SHA256" => {
            let Some(key) = trusted.get(&record.key_id) else {
                return false;
            };
            let sig = hmac_sha256(&key.key, payload.as_bytes());
            hex_encode(&sig) == record.sig_hex
        }
        "EXT" => {
            if let Ok(cmd) = env::var("IRONPORT_VERIFY_CMD") {
                run_verify_command(&cmd, &payload, &record.sig_hex)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn verify_provenance(prov: &str, content: &[u8]) -> bool {
    if let Some(build_hash) = parse_provenance_value(prov, "build_hash") {
        return build_hash == hash_bytes(content);
    }
    false
}

fn parse_provenance_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn load_revoked(path: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let key = line.trim();
            if !key.is_empty() {
                set.insert(key.to_string());
            }
        }
    }
    set
}

fn load_trusted(path: &Path) -> HashMap<String, TrustedKey> {
    let mut map = HashMap::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 2 {
                continue;
            }
            let key_id = parts[0].to_string();
            let key = match decode_hex(parts[1]) {
                Ok(key) => key,
                Err(_) => continue,
            };
            let prev_id = parts.get(2).map(|v| v.to_string());
            let expires_at = parts.get(3).and_then(|v| v.parse::<u64>().ok());
            map.insert(
                key_id.clone(),
                TrustedKey {
                    key_id,
                    key,
                    prev_id,
                    expires_at,
                },
            );
        }
    }
    map
}

fn hash_bytes(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ()> {
    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_value(bytes[i])?;
        let lo = hex_value(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_value(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

struct SignatureRecord {
    alg: String,
    key_id: String,
    prev_id: String,
    issued: u64,
    expires: u64,
    sig_hex: String,
}

struct TrustedKey {
    key_id: String,
    key: Vec<u8>,
    prev_id: Option<String>,
    expires_at: Option<u64>,
}

fn parse_signature(sig: &str) -> Option<SignatureRecord> {
    let parts: Vec<&str> = sig.trim().split(':').collect();
    if parts.len() != 7 || parts[0] != "SIG2" {
        return None;
    }
    Some(SignatureRecord {
        alg: parts[1].to_string(),
        key_id: parts[2].to_string(),
        prev_id: parts[3].to_string(),
        issued: parts[4].parse().ok()?,
        expires: parts[5].parse().ok()?,
        sig_hex: parts[6].to_string(),
    })
}

fn build_signature_payload(
    content: &[u8],
    key_id: &str,
    prev_id: &str,
    issued: u64,
    expires: u64,
) -> String {
    let hash = hash_bytes(content);
    format!(
        "v=2\nhash={hash}\nkey_id={key_id}\nprev_id={prev_id}\nissued={issued}\nexpires={expires}\n"
    )
}

fn validate_chain<'a>(
    mut key_id: &'a str,
    trusted: &'a HashMap<String, TrustedKey>,
    revoked: &HashSet<String>,
    now: u64,
) -> bool {
    for _ in 0..8 {
        let Some(key) = trusted.get(key_id) else {
            return false;
        };
        if revoked.contains(&key.key_id) {
            return false;
        }
        if let Some(expires) = key.expires_at {
            if expires < now {
                return false;
            }
        }
        let prev = match key.prev_id.as_deref() {
            Some("none") | Some("") | None => return true,
            Some(prev) => prev,
        };
        key_id = prev;
    }
    false
}

fn run_verify_command(cmd: &str, payload: &str, sig_hex: &str) -> bool {
    let mut parts = cmd.split_whitespace();
    let Some(program) = parts.next() else {
        return false;
    };
    let mut command = Command::new(program);
    for arg in parts {
        let arg = arg.replace("{sig}", sig_hex);
        command.arg(arg);
    }
    let mut child = match command.stdin(Stdio::piped()).stdout(Stdio::null()).spawn() {
        Ok(child) => child,
        Err(_) => return false,
    };
    if let Some(stdin) = child.stdin.as_mut() {
        if stdin.write_all(payload.as_bytes()).is_err() {
            return false;
        }
    }
    match child.wait() {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}
