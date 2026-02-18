use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use ironshim_rs::crypto::{hmac_sha256, Sha256};

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("ironport-repo <bind_addr> <repo_dir>");
        return;
    }
    let bind = &args[0];
    let repo_dir = PathBuf::from(&args[1]);
    let listener = TcpListener::bind(bind).expect("bind failed");
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            handle(stream, &repo_dir);
        }
    }
}

fn handle(mut stream: TcpStream, repo_dir: &PathBuf) {
    let mut buffer = [0u8; 4096];
    let Ok(n) = stream.read(&mut buffer) else {
        return;
    };
    let revoked = load_revoked(repo_dir);
    let trusted = load_trusted(repo_dir);
    let request = String::from_utf8_lossy(&buffer[..n]);
    let mut parts = request.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    if method != "GET" {
        respond(&mut stream, 405, "Method Not Allowed", b"");
        return;
    }
    if path == "/index" {
        let mut body = String::new();
        if let Ok(entries) = fs::read_dir(repo_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".sig") || name.ends_with(".prov") {
                        continue;
                    }
                    let file_path = repo_dir.join(name);
                    if is_artifact_valid(&file_path, &revoked, &trusted) {
                        body.push_str(name);
                        body.push('\n');
                    }
                }
            }
        }
        respond(&mut stream, 200, "OK", body.as_bytes());
        return;
    }
    if let Some(name) = path.strip_prefix("/file/") {
        let file_path = repo_dir.join(name);
        if !file_path.exists() {
            respond(&mut stream, 404, "Not Found", b"");
            return;
        }
        if name.ends_with(".sig") || name.ends_with(".prov") {
            match fs::read(&file_path) {
                Ok(body) => respond(&mut stream, 200, "OK", &body),
                Err(_) => respond(&mut stream, 404, "Not Found", b""),
            }
            return;
        }
        if !is_artifact_valid(&file_path, &revoked, &trusted) {
            respond(&mut stream, 403, "Forbidden", b"");
            return;
        }
        match fs::read(&file_path) {
            Ok(body) => respond(&mut stream, 200, "OK", &body),
            Err(_) => respond(&mut stream, 404, "Not Found", b""),
        }
        return;
    }
    respond(&mut stream, 404, "Not Found", b"");
}

fn respond(stream: &mut TcpStream, code: u16, text: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {code} {text}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
}

fn is_artifact_valid(
    file_path: &PathBuf,
    revoked: &HashSet<String>,
    trusted: &HashMap<String, TrustedKey>,
) -> bool {
    let mut sig_path = file_path.clone();
    sig_path.set_extension("sig");
    let mut prov_path = file_path.clone();
    prov_path.set_extension("prov");
    let Ok(sig) = fs::read_to_string(sig_path) else {
        return false;
    };
    let Ok(content) = fs::read(file_path) else {
        return false;
    };
    if !verify_signature(&sig, &content, revoked, trusted) {
        return false;
    }
    if !prov_path.exists() {
        return false;
    }
    let Ok(prov) = fs::read_to_string(prov_path) else {
        return false;
    };
    if let Some(build_hash) = parse_provenance_value(&prov, "build_hash") {
        let actual = hash_bytes(&content);
        if build_hash != actual {
            return false;
        }
    } else {
        return false;
    }
    true
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

fn load_revoked(repo_dir: &PathBuf) -> HashSet<String> {
    let mut set = HashSet::new();
    let path = repo_dir.join("revoked.keys");
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

fn load_trusted(repo_dir: &PathBuf) -> HashMap<String, TrustedKey> {
    let mut map = HashMap::new();
    let path = repo_dir.join("trusted.keys");
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
