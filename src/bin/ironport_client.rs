#[path = "shared/tooling_support.rs"]
mod tooling_support;

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use tooling_support::{
    hash_bytes, intoto_path, load_revoked, load_trusted, slsa_path, spdx_path, verify_signature,
};

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
        return;
    }
    if args.len() == 2 && args[1] == "index" {
        if let Ok((_, body)) = request(&args[0], "/index") {
            println!("{body}");
        }
        return;
    }
    if args.len() == 4 && args[1] == "get" {
        let name = &args[2];
        let out = PathBuf::from(&args[3]);
        if let Ok((status, body)) = request(&args[0], &format!("/file/{name}")) {
            if status == 200 {
                let _ = fs::write(out, body.as_bytes());
            }
        }
        return;
    }
    if args.len() == 4 && args[1] == "get-verified" {
        let name = &args[2];
        let out = PathBuf::from(&args[3]);
        match fetch_verified(&args[0], name, &out) {
            Ok(()) => {}
            Err(err) => {
                eprintln!("verification failed: {err}");
                std::process::exit(1);
            }
        }
        return;
    }
    usage();
}

fn usage() {
    eprintln!("ironport-client <addr> index");
    eprintln!("ironport-client <addr> get <name> <out>");
    eprintln!("ironport-client <addr> get-verified <name> <out>");
}

fn fetch_verified(addr: &str, name: &str, out: &Path) -> std::io::Result<()> {
    let revoked = load_revoked(Path::new("revoked.keys"));
    let trusted = load_trusted(Path::new("trusted.keys"));

    let root = fetch_metadata(addr, "root.json", &revoked, &trusted, "tuf-root")?;
    let targets = fetch_metadata(addr, "targets.json", &revoked, &trusted, "tuf-targets")?;
    let snapshot = fetch_metadata(addr, "snapshot.json", &revoked, &trusted, "tuf-snapshot")?;
    let timestamp = fetch_metadata(addr, "timestamp.json", &revoked, &trusted, "tuf-timestamp")?;

    verify_snapshot_chain(&root, &targets, &snapshot, &timestamp)?;
    update_rollback_state(addr, &snapshot, &timestamp)?;

    let (status, body) = request(addr, &format!("/file/{name}"))?;
    if status != 200 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "artifact not found",
        ));
    }
    let artifact = body.into_bytes();
    let artifact_hash = hash_bytes(&artifact);
    let (_, sig) = request(addr, &format!("/file/{name}.sig"))?;
    if !verify_signature(&sig, &artifact, &revoked, &trusted, "artifact") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "artifact signature",
        ));
    }
    verify_targets_entry(&targets, name, &artifact_hash, artifact.len() as u64)?;

    let (_, prov) = request(addr, &format!("/file/{name}.prov"))?;
    if parse_value(&prov, "build_hash").as_deref() != Some(artifact_hash.as_str()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "provenance hash",
        ));
    }

    let intoto_name = with_extension(name, "intoto.json");
    let slsa_name = with_extension(name, "slsa.json");
    let spdx_name = with_extension(name, "spdx.json");
    let (_, intoto) = request(addr, &format!("/file/{intoto_name}"))?;
    let (_, slsa) = request(addr, &format!("/file/{slsa_name}"))?;
    let (_, spdx) = request(addr, &format!("/file/{spdx_name}"))?;

    if !intoto.contains(&format!("\"sha256\": \"{artifact_hash}\"")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "in-toto subject",
        ));
    }
    if parse_json_field(&slsa, "subject_sha256").as_deref() != Some(artifact_hash.as_str()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "slsa subject",
        ));
    }
    if parse_json_field(&spdx, "subject_sha256").as_deref() != Some(artifact_hash.as_str()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "spdx subject",
        ));
    }

    fs::write(out, &artifact)?;
    fs::write(intoto_path(out), intoto.as_bytes())?;
    fs::write(slsa_path(out), slsa.as_bytes())?;
    fs::write(spdx_path(out), spdx.as_bytes())?;
    Ok(())
}

fn fetch_metadata(
    addr: &str,
    name: &str,
    revoked: &std::collections::HashSet<String>,
    trusted: &std::collections::HashMap<String, tooling_support::TrustedKey>,
    context: &str,
) -> std::io::Result<String> {
    let (status, body) = request(addr, &format!("/metadata/{name}"))?;
    if status != 200 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "metadata missing",
        ));
    }
    let (_, sig) = request(addr, &format!("/metadata/{name}.sig"))?;
    if !verify_signature(&sig, body.as_bytes(), revoked, trusted, context) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "metadata signature",
        ));
    }
    Ok(body)
}

fn verify_snapshot_chain(
    root: &str,
    targets: &str,
    snapshot: &str,
    timestamp: &str,
) -> std::io::Result<()> {
    let root_hash = hash_bytes(root.as_bytes());
    let targets_hash = hash_bytes(targets.as_bytes());
    let snapshot_hash = hash_bytes(snapshot.as_bytes());

    if parse_meta_hash(snapshot, "root.json").as_deref() != Some(root_hash.as_str()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "snapshot root hash",
        ));
    }
    if parse_meta_hash(snapshot, "targets.json").as_deref() != Some(targets_hash.as_str()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "snapshot targets hash",
        ));
    }
    if parse_json_field(timestamp, "sha256").as_deref() != Some(snapshot_hash.as_str()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "timestamp snapshot hash",
        ));
    }
    let now = tooling_support::current_epoch();
    for body in [root, targets, snapshot, timestamp] {
        let Some(expires) = parse_json_u64(body, "expires") else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "metadata expiry",
            ));
        };
        if expires < now {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "metadata expired",
            ));
        }
    }
    Ok(())
}

fn verify_targets_entry(
    targets: &str,
    name: &str,
    artifact_hash: &str,
    length: u64,
) -> std::io::Result<()> {
    let marker = format!("\"{name}\": {{");
    let start = targets.find(&marker).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "target missing")
    })?;
    let body = &targets[start..];
    let recorded_hash = parse_json_field(body, "sha256").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "target hash missing")
    })?;
    let recorded_len = parse_json_u64(body, "length").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "target length missing",
        )
    })?;
    if recorded_hash != artifact_hash || recorded_len != length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "target mismatch",
        ));
    }
    Ok(())
}

fn update_rollback_state(addr: &str, snapshot: &str, timestamp: &str) -> std::io::Result<()> {
    let state_dir = PathBuf::from(".ironport-client");
    fs::create_dir_all(&state_dir)?;
    let state_path = state_dir.join(format!("{}.state", sanitize(addr)));
    let snapshot_version = parse_json_u64(snapshot, "version").unwrap_or(0);
    let timestamp_version = parse_json_u64(timestamp, "version").unwrap_or(0);
    if state_path.exists() {
        let content = fs::read_to_string(&state_path)?;
        let old_snapshot = parse_value(&content, "snapshot_version")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let old_timestamp = parse_value(&content, "timestamp_version")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        if snapshot_version < old_snapshot || timestamp_version < old_timestamp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "rollback detected",
            ));
        }
    }
    let state =
        format!("snapshot_version={snapshot_version}\ntimestamp_version={timestamp_version}\n");
    fs::write(state_path, state.as_bytes())?;
    Ok(())
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn with_extension(name: &str, extension: &str) -> String {
    let mut path = PathBuf::from(name);
    path.set_extension(extension);
    path.to_string_lossy().to_string()
}

fn request(addr: &str, path: &str) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(addr)?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let mut lines = response.lines();
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

fn parse_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        if let Some((left, right)) = line.split_once('=') {
            if left.trim() == key {
                return Some(right.trim().to_string());
            }
        }
    }
    None
}

fn parse_json_field(content: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\": \"");
    let start = content.find(&needle)? + needle.len();
    let rest = &content[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn parse_json_u64(content: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\": ");
    let start = content.find(&needle)? + needle.len();
    let rest = &content[start..];
    let end = rest
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn parse_meta_hash(content: &str, name: &str) -> Option<String> {
    let marker = format!("\"{name}\": {{");
    let start = content.find(&marker)?;
    parse_json_field(&content[start..], "sha256")
}
