#[path = "shared/tooling_support.rs"]
mod tooling_support;

use std::collections::HashMap;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use tooling_support::{
    canonical_repo_path, current_epoch, file_hash, intoto_path, json_escape, load_revoked,
    load_trusted, primary_artifact_name, sign_blob, slsa_path, spdx_path, verify_signature,
};

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("ironport-repo <bind_addr> <repo_dir>");
        return;
    }
    let bind = &args[0];
    let repo_dir = PathBuf::from(&args[1]);
    let listener = match TcpListener::bind(bind) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("bind failed: {err}");
            std::process::exit(1);
        }
    };
    for stream in listener.incoming().flatten() {
        handle(stream, &repo_dir);
    }
}

fn handle(mut stream: TcpStream, repo_dir: &Path) {
    let mut buffer = [0u8; 4096];
    let Ok(n) = stream.read(&mut buffer) else {
        return;
    };
    let revoked = load_revoked(&repo_dir.join("revoked.keys"));
    let trusted = load_trusted(&repo_dir.join("trusted.keys"));
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
        if let Ok(entries) = collect_artifacts(repo_dir, &revoked, &trusted) {
            for entry in entries {
                let _ = writeln!(&mut body, "{}", entry.name);
            }
        }
        respond(&mut stream, 200, "OK", body.as_bytes());
        return;
    }
    if let Some(name) = path.strip_prefix("/metadata/") {
        match build_metadata_bundle(repo_dir, &revoked, &trusted) {
            Ok(bundle) => {
                if let Some(body) = bundle.get(name) {
                    respond(&mut stream, 200, "OK", body.as_bytes());
                } else if let Some(sig) = bundle.get_sig(name) {
                    respond(&mut stream, 200, "OK", sig.as_bytes());
                } else {
                    respond(&mut stream, 404, "Not Found", b"");
                }
            }
            Err(_) => respond(&mut stream, 500, "Internal Server Error", b""),
        }
        return;
    }
    if let Some(name) = path.strip_prefix("/file/") {
        match serve_file(name, repo_dir, &revoked, &trusted) {
            Ok(body) => respond(&mut stream, 200, "OK", &body),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                respond(&mut stream, 403, "Forbidden", b"")
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                respond(&mut stream, 404, "Not Found", b"")
            }
            Err(_) => respond(&mut stream, 500, "Internal Server Error", b""),
        }
        return;
    }
    respond(&mut stream, 404, "Not Found", b"");
}

fn serve_file(
    name: &str,
    repo_dir: &Path,
    revoked: &std::collections::HashSet<String>,
    trusted: &HashMap<String, tooling_support::TrustedKey>,
) -> std::io::Result<Vec<u8>> {
    let file_path = canonical_repo_path(repo_dir, name)?;
    if !file_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
    }
    if primary_artifact_name(name) {
        if !is_artifact_valid(&file_path, revoked, trusted)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid artifact",
            ));
        }
        return fs::read(file_path);
    }

    let base_path = if name.ends_with(".sig") || name.ends_with(".prov") {
        file_path.with_extension("")
    } else if name.ends_with(".intoto.json") {
        strip_suffix_path(&file_path, ".intoto.json")
    } else if name.ends_with(".slsa.json") {
        strip_suffix_path(&file_path, ".slsa.json")
    } else if name.ends_with(".spdx.json") {
        strip_suffix_path(&file_path, ".spdx.json")
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsupported sidecar",
        ));
    };
    if !is_artifact_valid(&base_path, revoked, trusted)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid base artifact",
        ));
    }
    fs::read(file_path)
}

fn strip_suffix_path(path: &Path, suffix: &str) -> PathBuf {
    let owned = path.to_string_lossy();
    let trimmed = owned.strip_suffix(suffix).unwrap_or(&owned);
    PathBuf::from(trimmed)
}

fn respond(stream: &mut TcpStream, code: u16, text: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {code} {text}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
}

#[derive(Clone)]
struct ArtifactEntry {
    name: String,
    length: u64,
    sha256: String,
    intoto_sha256: String,
    slsa_sha256: String,
    spdx_sha256: String,
}

fn collect_artifacts(
    repo_dir: &Path,
    revoked: &std::collections::HashSet<String>,
    trusted: &HashMap<String, tooling_support::TrustedKey>,
) -> std::io::Result<Vec<ArtifactEntry>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(repo_dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(|value| value.to_string()) else {
            continue;
        };
        if !primary_artifact_name(&name) {
            continue;
        }
        let path = entry.path();
        if !path.is_file() || !is_artifact_valid(&path, revoked, trusted)? {
            continue;
        }
        entries.push(ArtifactEntry {
            length: entry.metadata()?.len(),
            sha256: file_hash(&path)?,
            intoto_sha256: file_hash(&intoto_path(&path))?,
            slsa_sha256: file_hash(&slsa_path(&path))?,
            spdx_sha256: file_hash(&spdx_path(&path))?,
            name,
        });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn is_artifact_valid(
    file_path: &Path,
    revoked: &std::collections::HashSet<String>,
    trusted: &HashMap<String, tooling_support::TrustedKey>,
) -> std::io::Result<bool> {
    if !file_path.exists() {
        return Ok(false);
    }
    let mut sig_path = PathBuf::from(file_path);
    sig_path.set_extension("sig");
    let mut prov_path = PathBuf::from(file_path);
    prov_path.set_extension("prov");
    let intoto = intoto_path(file_path);
    let slsa = slsa_path(file_path);
    let spdx = spdx_path(file_path);
    if !sig_path.exists()
        || !prov_path.exists()
        || !intoto.exists()
        || !slsa.exists()
        || !spdx.exists()
    {
        return Ok(false);
    }
    let sig = fs::read_to_string(sig_path)?;
    let content = fs::read(file_path)?;
    if !verify_signature(&sig, &content, revoked, trusted, "artifact") {
        return Ok(false);
    }
    let hash = file_hash(file_path)?;
    let prov = fs::read_to_string(prov_path)?;
    if parse_value(&prov, "build_hash").as_deref() != Some(hash.as_str()) {
        return Ok(false);
    }
    let intoto_body = fs::read_to_string(intoto)?;
    if !intoto_body.contains(&format!("\"sha256\": \"{hash}\"")) {
        return Ok(false);
    }
    let slsa_body = fs::read_to_string(slsa)?;
    if parse_json_field(&slsa_body, "subject_sha256").as_deref() != Some(hash.as_str()) {
        return Ok(false);
    }
    let spdx_body = fs::read_to_string(spdx)?;
    if parse_json_field(&spdx_body, "subject_sha256").as_deref() != Some(hash.as_str()) {
        return Ok(false);
    }
    Ok(true)
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

struct MetadataBundle {
    root: String,
    root_sig: String,
    targets: String,
    targets_sig: String,
    snapshot: String,
    snapshot_sig: String,
    timestamp: String,
    timestamp_sig: String,
}

impl MetadataBundle {
    fn get(&self, name: &str) -> Option<&String> {
        match name {
            "root.json" => Some(&self.root),
            "targets.json" => Some(&self.targets),
            "snapshot.json" => Some(&self.snapshot),
            "timestamp.json" => Some(&self.timestamp),
            _ => None,
        }
    }

    fn get_sig(&self, name: &str) -> Option<&String> {
        match name {
            "root.json.sig" => Some(&self.root_sig),
            "targets.json.sig" => Some(&self.targets_sig),
            "snapshot.json.sig" => Some(&self.snapshot_sig),
            "timestamp.json.sig" => Some(&self.timestamp_sig),
            _ => None,
        }
    }
}

fn build_metadata_bundle(
    repo_dir: &Path,
    revoked: &std::collections::HashSet<String>,
    trusted: &HashMap<String, tooling_support::TrustedKey>,
) -> std::io::Result<MetadataBundle> {
    let artifacts = collect_artifacts(repo_dir, revoked, trusted)?;
    let root_version = env::var("IRONPORT_TUF_ROOT_VERSION")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1);
    let dynamic_version = current_epoch().max(1);
    let root_expires = current_epoch().saturating_add(365 * 24 * 60 * 60);
    let metadata_expires = current_epoch().saturating_add(24 * 60 * 60);

    let mut keys = String::new();
    let mut first = true;
    let mut trusted_keys = trusted.keys().collect::<Vec<_>>();
    trusted_keys.sort();
    for key in trusted_keys {
        if !first {
            keys.push_str(", ");
        }
        first = false;
        let _ = write!(
            &mut keys,
            "\"{}\": {{\"keytype\": \"shared\", \"scheme\": \"sig3\"}}",
            json_escape(key)
        );
    }

    let mut target_entries = String::new();
    for (index, entry) in artifacts.iter().enumerate() {
        if index != 0 {
            target_entries.push_str(",\n");
        }
        let _ = write!(
            &mut target_entries,
            concat!(
                "    \"{}\": {{\"length\": {}, \"hashes\": {{\"sha256\": \"{}\"}}, ",
                "\"custom\": {{\"intoto_sha256\": \"{}\", \"slsa_sha256\": \"{}\", \"spdx_sha256\": \"{}\"}}}}"
            ),
            json_escape(&entry.name),
            entry.length,
            entry.sha256,
            entry.intoto_sha256,
            entry.slsa_sha256,
            entry.spdx_sha256,
        );
    }

    let root = format!(
        concat!(
            "{{\n",
            "  \"_type\": \"root\",\n",
            "  \"spec_version\": \"1.0.19\",\n",
            "  \"version\": {},\n",
            "  \"expires\": {},\n",
            "  \"keys\": {{{}}},\n",
            "  \"roles\": {{\"root\": {{}}, \"targets\": {{}}, \"snapshot\": {{}}, \"timestamp\": {{}}}}\n",
            "}}\n"
        ),
        root_version, root_expires, keys
    );
    let targets = format!(
        concat!(
            "{{\n",
            "  \"_type\": \"targets\",\n",
            "  \"version\": {},\n",
            "  \"expires\": {},\n",
            "  \"targets\": {{\n{}\n  }}\n",
            "}}\n"
        ),
        dynamic_version, metadata_expires, target_entries
    );
    let snapshot = format!(
        concat!(
            "{{\n",
            "  \"_type\": \"snapshot\",\n",
            "  \"version\": {},\n",
            "  \"expires\": {},\n",
            "  \"meta\": {{\n",
            "    \"root.json\": {{\"version\": {}, \"sha256\": \"{}\"}},\n",
            "    \"targets.json\": {{\"version\": {}, \"sha256\": \"{}\"}}\n",
            "  }}\n",
            "}}\n"
        ),
        dynamic_version,
        metadata_expires,
        root_version,
        tooling_support::hash_bytes(root.as_bytes()),
        dynamic_version,
        tooling_support::hash_bytes(targets.as_bytes()),
    );
    let timestamp = format!(
        concat!(
            "{{\n",
            "  \"_type\": \"timestamp\",\n",
            "  \"version\": {},\n",
            "  \"expires\": {},\n",
            "  \"snapshot\": {{\"version\": {}, \"sha256\": \"{}\"}}\n",
            "}}\n"
        ),
        dynamic_version,
        current_epoch().saturating_add(10 * 60),
        dynamic_version,
        tooling_support::hash_bytes(snapshot.as_bytes()),
    );

    Ok(MetadataBundle {
        root_sig: sign_blob(root.as_bytes(), "tuf-root")?,
        targets_sig: sign_blob(targets.as_bytes(), "tuf-targets")?,
        snapshot_sig: sign_blob(snapshot.as_bytes(), "tuf-snapshot")?,
        timestamp_sig: sign_blob(timestamp.as_bytes(), "tuf-timestamp")?,
        root,
        targets,
        snapshot,
        timestamp,
    })
}
