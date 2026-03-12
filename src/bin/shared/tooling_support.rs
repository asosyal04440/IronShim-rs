#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::env;
use std::io;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use ironshim_rs::crypto::{hmac_sha256, Sha256};

pub fn current_epoch() -> u64 {
    env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        })
}

pub fn hash_bytes(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    hex_encode(&digest)
}

pub fn file_hash(path: &Path) -> io::Result<String> {
    let content = std::fs::read(path)?;
    Ok(hash_bytes(&content))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hex(input: &str) -> io::Result<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "hex length"));
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

fn hex_value(b: u8) -> io::Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "hex char")),
    }
}

#[derive(Clone)]
pub struct TrustedKey {
    pub key_id: String,
    pub key: Vec<u8>,
    pub prev_id: Option<String>,
    pub expires_at: Option<u64>,
}

pub struct SignatureRecord {
    pub alg: String,
    pub key_id: String,
    pub prev_id: String,
    pub issued: u64,
    pub expires: u64,
    pub context: String,
    pub sig_hex: String,
}

pub fn load_revoked(path: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let key = line.trim();
            if !key.is_empty() {
                set.insert(key.to_string());
            }
        }
    }
    set
}

pub fn load_trusted(path: &Path) -> HashMap<String, TrustedKey> {
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(path) {
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
            let prev_id = parts.get(2).map(|value| value.to_string());
            let expires_at = parts.get(3).and_then(|value| value.parse::<u64>().ok());
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

pub fn build_signature_payload(
    content: &[u8],
    key_id: &str,
    prev_id: &str,
    issued: u64,
    expires: u64,
    context: &str,
) -> String {
    let hash = hash_bytes(content);
    format!(
        "v=3\ncontext={context}\nhash={hash}\nkey_id={key_id}\nprev_id={prev_id}\nissued={issued}\nexpires={expires}\n"
    )
}

pub fn sign_blob(content: &[u8], context: &str) -> io::Result<String> {
    let issued = current_epoch();
    let key_id = env::var("IRONPORT_KEY_ID").unwrap_or_else(|_| "local-key-1".to_string());
    let prev_id = env::var("IRONPORT_PREV_KEY_ID").unwrap_or_else(|_| "none".to_string());
    let expires = env::var("IRONPORT_KEY_EXPIRES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| issued.saturating_add(90 * 24 * 60 * 60));
    let payload = build_signature_payload(content, &key_id, &prev_id, issued, expires, context);
    let (alg, sig_hex) = if let Ok(cmd) = env::var("IRONPORT_SIGN_CMD") {
        let sig = run_sign_command(&cmd, &payload)?;
        ("EXT", sig)
    } else {
        let key = load_signing_key()?;
        let sig = hmac_sha256(&key, payload.as_bytes());
        ("HMAC-SHA256", hex_encode(&sig))
    };
    Ok(format!(
        "SIG3:{alg}:{key_id}:{prev_id}:{issued}:{expires}:{context}:{sig_hex}"
    ))
}

pub fn verify_signature(
    sig: &str,
    content: &[u8],
    revoked: &HashSet<String>,
    trusted: &HashMap<String, TrustedKey>,
    expected_context: &str,
) -> bool {
    let record = match parse_signature(sig) {
        Some(record) => record,
        None => return false,
    };
    if record.context != expected_context || revoked.contains(&record.key_id) {
        return false;
    }
    let now = current_epoch();
    if record.issued > now || record.expires < now {
        return false;
    }
    if !validate_chain(&record.key_id, trusted, revoked, now) {
        return false;
    }
    let payload = build_signature_payload(
        content,
        &record.key_id,
        &record.prev_id,
        record.issued,
        record.expires,
        &record.context,
    );
    match record.alg.as_str() {
        "HMAC-SHA256" => {
            let Some(key) = trusted.get(&record.key_id) else {
                return false;
            };
            let sig = hmac_sha256(&key.key, payload.as_bytes());
            hex_encode(&sig) == record.sig_hex
        }
        "EXT" => env::var("IRONPORT_VERIFY_CMD")
            .ok()
            .map(|cmd| run_verify_command(&cmd, &payload, &record.sig_hex))
            .unwrap_or(false),
        _ => false,
    }
}

pub fn parse_signature(sig: &str) -> Option<SignatureRecord> {
    let parts: Vec<&str> = sig.trim().split(':').collect();
    if parts.len() != 8 || parts[0] != "SIG3" {
        return None;
    }
    Some(SignatureRecord {
        alg: parts[1].to_string(),
        key_id: parts[2].to_string(),
        prev_id: parts[3].to_string(),
        issued: parts[4].parse().ok()?,
        expires: parts[5].parse().ok()?,
        context: parts[6].to_string(),
        sig_hex: parts[7].to_string(),
    })
}

pub fn canonical_repo_path(root: &Path, requested: &str) -> io::Result<PathBuf> {
    let requested_path = Path::new(requested);
    if requested_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "absolute path",
        ));
    }
    let mut candidate = PathBuf::from(root);
    for component in requested_path.components() {
        match component {
            Component::Normal(part) => candidate.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "path traversal",
                ));
            }
        }
    }
    Ok(candidate)
}

pub fn primary_artifact_name(name: &str) -> bool {
    !name.ends_with(".sig")
        && !name.ends_with(".prov")
        && !name.ends_with(".intoto.json")
        && !name.ends_with(".slsa.json")
        && !name.ends_with(".spdx.json")
        && !name.ends_with(".root.json")
        && !name.ends_with(".targets.json")
        && !name.ends_with(".snapshot.json")
        && !name.ends_with(".timestamp.json")
        && name != "trusted.keys"
        && name != "revoked.keys"
}

pub fn intoto_path(output: &Path) -> PathBuf {
    let mut path = PathBuf::from(output);
    path.set_extension("intoto.json");
    path
}

pub fn slsa_path(output: &Path) -> PathBuf {
    let mut path = PathBuf::from(output);
    path.set_extension("slsa.json");
    path
}

pub fn spdx_path(output: &Path) -> PathBuf {
    let mut path = PathBuf::from(output);
    path.set_extension("spdx.json");
    path
}

pub fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn load_signing_key() -> io::Result<Vec<u8>> {
    if let Ok(hex) = env::var("IRONPORT_SIGNING_KEY_HEX") {
        return decode_hex(hex.trim());
    }
    if let Ok(raw) = env::var("IRONPORT_SIGNING_KEY") {
        return Ok(raw.into_bytes());
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "missing signing key",
    ))
}

pub fn run_sign_command(cmd: &str, payload: &str) -> io::Result<String> {
    let mut parts = cmd.split_whitespace();
    let program = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sign cmd"))?;
    let mut command = Command::new(program);
    for arg in parts {
        command.arg(arg);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(payload.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "sign command failed"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn run_verify_command(cmd: &str, payload: &str, sig_hex: &str) -> bool {
    let mut parts = cmd.split_whitespace();
    let Some(program) = parts.next() else {
        return false;
    };
    let mut command = Command::new(program);
    for arg in parts {
        command.arg(arg.replace("{sig}", sig_hex));
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
    child.wait().map(|status| status.success()).unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::{canonical_repo_path, primary_artifact_name};
    use std::path::Path;

    #[test]
    fn canonical_repo_path_rejects_parent_segments() {
        let result = canonical_repo_path(Path::new("repo"), "../secret");
        assert!(result.is_err());
    }

    #[test]
    fn primary_artifact_filter_excludes_sidecars() {
        assert!(primary_artifact_name("driver.bin"));
        assert!(!primary_artifact_name("driver.sig"));
        assert!(!primary_artifact_name("driver.intoto.json"));
    }
}
