#[path = "shared/tooling_support.rs"]
mod tooling_support;

use ironshim_rs::crypto::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;
use tooling_support::{
    current_epoch, hash_bytes as shared_hash_bytes, intoto_path, json_escape, sign_blob, slsa_path,
    spdx_path,
};

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
        return;
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "extract" => {
            if args.len() != 4 {
                usage();
                return;
            }
            let linux = PathBuf::from(&args[0]);
            let ported = PathBuf::from(&args[1]);
            let version = args[2].clone();
            let out = PathBuf::from(&args[3]);
            if let Err(err) = extract_patterns(&linux, &ported, &version, &out) {
                eprintln!("extract failed: {err}");
                std::process::exit(1);
            }
        }
        "apply" => {
            let mut stealth = false;
            let mut sign = true;
            let mut linux_version = None;
            let mut driver_family = None;
            let mut force = false;
            let mut no_cache = false;
            args.retain(|arg| match arg.as_str() {
                "--stealth" => {
                    stealth = true;
                    false
                }
                "--no-sign" => {
                    sign = false;
                    false
                }
                "--force" => {
                    force = true;
                    false
                }
                "--no-cache" => {
                    no_cache = true;
                    false
                }
                _ if arg.starts_with("--linux-version=") => {
                    linux_version = arg.split_once('=').map(|(_, v)| v.to_string());
                    false
                }
                _ if arg.starts_with("--driver-family=") => {
                    driver_family = arg.split_once('=').map(|(_, v)| v.to_string());
                    false
                }
                _ => true,
            });
            if args.len() != 3 {
                usage();
                return;
            }
            let pattern = PathBuf::from(&args[0]);
            let input = PathBuf::from(&args[1]);
            let output = PathBuf::from(&args[2]);
            if let Err(err) = apply_patterns(
                &pattern,
                &input,
                &output,
                stealth,
                sign,
                linux_version,
                driver_family,
                force,
                no_cache,
            ) {
                eprintln!("apply failed: {err}");
                std::process::exit(1);
            }
        }
        "suggest" => {
            if args.len() != 3 {
                usage();
                return;
            }
            let pattern = PathBuf::from(&args[0]);
            let input = PathBuf::from(&args[1]);
            let output = PathBuf::from(&args[2]);
            if let Err(err) = suggest_patterns(&pattern, &input, &output) {
                eprintln!("suggest failed: {err}");
                std::process::exit(1);
            }
        }
        _ => usage(),
    }
}

fn usage() {
    eprintln!("ironport extract <linux.c> <ported.c> <version> <out.toml>");
    eprintln!(
        "ironport apply [--stealth] [--no-sign] [--force] [--no-cache] [--linux-version=V] [--driver-family=F] <pattern.toml> <input> <output>"
    );
    eprintln!("ironport suggest <pattern.toml> <input.c> <out.toml>");
}

fn extract_patterns(linux: &Path, ported: &Path, version: &str, out: &Path) -> io::Result<()> {
    let linux_src = fs::read_to_string(linux)?;
    let ported_src = fs::read_to_string(ported)?;
    let linux_calls = collect_calls(&linux_src);
    let ported_calls = collect_calls(&ported_src);
    let manifest = extract_manifest(&linux_src);
    let metadata = PatternMetadata {
        version: version.to_string(),
        linux_version: "unknown".to_string(),
        driver_family: "unknown".to_string(),
        confidence: 0.5,
        review_required: true,
    };
    let build = BuildSettings {
        thin_lto: true,
        incremental: true,
        lto_cache: true,
    };

    let mut mapping = BTreeMap::new();
    for call in linux_calls {
        if ported_calls.contains(&call) {
            mapping.insert(call.clone(), call);
        } else {
            mapping.insert(call, "UNKNOWN".to_string());
        }
    }

    let toml = render_toml(&metadata, &build, &mapping, &manifest);
    fs::write(out, toml.as_bytes())?;
    let _ = sign_output(out);
    let _ = write_pattern_provenance(out, linux, ported);
    store_pattern(version, out)?;
    store_corpus(version, linux, ported)?;
    Ok(())
}

fn apply_patterns(
    pattern: &Path,
    input: &Path,
    output: &Path,
    stealth: bool,
    sign: bool,
    linux_version: Option<String>,
    driver_family: Option<String>,
    force: bool,
    no_cache: bool,
) -> io::Result<()> {
    if stealth {
        run_stealth_worker();
    }
    let content = fs::read_to_string(input)?;
    let pattern_data = parse_pattern(pattern)?;
    if let Some(expected) = linux_version {
        if pattern_data.metadata.linux_version != "unknown"
            && pattern_data.metadata.linux_version != expected
        {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "linux version mismatch",
            ));
        }
    }
    if let Some(expected) = driver_family {
        if pattern_data.metadata.driver_family != "unknown"
            && pattern_data.metadata.driver_family != expected
        {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "driver family mismatch",
            ));
        }
    }
    if pattern_data.metadata.review_required && pattern_data.metadata.confidence < 0.75 && !force {
        return Err(io::Error::new(io::ErrorKind::Other, "review required"));
    }
    if !no_cache {
        if let Ok(true) = cache_hit(input, output) {
            return Ok(());
        }
    }
    let mut transformed = content;
    let external_lto = env::var("IRONPORT_LTO_CMD").ok();
    for (from, to) in &pattern_data.mapping {
        if to != "UNKNOWN" {
            transformed = transformed.replace(from, to);
        }
    }
    if input.extension().and_then(|v| v.to_str()) == Some("ll") {
        transformed = mock_binary_patch(&transformed);
    }
    if input.extension().and_then(|v| v.to_str()) == Some("bc") {
        transformed = mock_binary_patch(&transformed);
    }
    if pattern_data.build.thin_lto {
        transformed = thin_lto_pass(&transformed);
    }
    let rollback = fs::read(output).ok();
    if pattern_data.build.incremental && external_lto.is_none() {
        if let Ok(true) = incremental_cache_hit(&transformed, output) {
            return Ok(());
        }
    }
    fs::write(output, transformed.as_bytes())?;
    if let Some(ref cmd) = external_lto {
        run_external_lto(cmd, output, output)?;
    }
    if pattern_data.build.incremental && external_lto.is_none() {
        let _ = update_incremental_cache(&transformed, output, pattern_data.build.lto_cache);
    }
    if sign {
        if let Err(err) = sign_output(output) {
            if let Some(prev) = rollback {
                let _ = fs::write(output, prev);
            }
            return Err(err);
        }
    }
    let _ = write_output_provenance(output, input, &pattern_data.build);
    let _ = write_attestation_bundle(output, input, &pattern_data);
    if !no_cache {
        let _ = update_cache(input, output);
    }
    audit_log("apply", output);
    Ok(())
}

fn suggest_patterns(pattern: &Path, input: &Path, output: &Path) -> io::Result<()> {
    let content = fs::read_to_string(input)?;
    let mut pattern_data = parse_pattern(pattern)?;
    let calls = collect_calls(&content);
    for call in calls {
        if let Some(value) = pattern_data.mapping.get_mut(&call) {
            if value == "UNKNOWN" {
                *value = format!("shim_{call}");
            }
        }
    }
    let manifest = extract_manifest(&content);
    pattern_data.metadata.version = "suggested".to_string();
    let toml = render_toml(
        &pattern_data.metadata,
        &pattern_data.build,
        &pattern_data.mapping,
        &manifest,
    );
    fs::write(output, toml.as_bytes())?;
    Ok(())
}

fn store_pattern(version: &str, out: &Path) -> io::Result<()> {
    let base = PathBuf::from(".ironport").join("patterns");
    fs::create_dir_all(&base)?;
    let dest = base.join(format!("{version}.toml"));
    fs::copy(out, dest)?;
    Ok(())
}

fn render_toml(
    metadata: &PatternMetadata,
    build: &BuildSettings,
    mapping: &BTreeMap<String, String>,
    manifest: &ManifestInfo,
) -> String {
    let mut out = String::new();
    let _ = writeln!(&mut out, "[metadata]");
    let _ = writeln!(&mut out, "version = \"{}\"", metadata.version);
    let _ = writeln!(&mut out, "linux_version = \"{}\"", metadata.linux_version);
    let _ = writeln!(&mut out, "driver_family = \"{}\"", metadata.driver_family);
    let _ = writeln!(&mut out, "confidence = {}", metadata.confidence);
    let _ = writeln!(&mut out, "review_required = {}", metadata.review_required);
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "[mapping]");
    for (k, v) in mapping {
        let _ = writeln!(&mut out, "{k} = \"{v}\"");
    }
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "[build]");
    let _ = writeln!(&mut out, "thin_lto = {}", build.thin_lto);
    let _ = writeln!(&mut out, "incremental = {}", build.incremental);
    let _ = writeln!(&mut out, "lto_cache = {}", build.lto_cache);
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "[binary_patch]");
    for (k, v) in mapping {
        let _ = writeln!(&mut out, "{k} = \"{v}\"");
    }
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "[manifest]");
    let _ = writeln!(&mut out, "bars = [{}]", manifest.bars.join(", "));
    let _ = writeln!(&mut out, "irqs = [{}]", manifest.irqs.join(", "));
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "[signing]");
    let _ = writeln!(&mut out, "mode = \"sig2\"");
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "[stealth]");
    let _ = writeln!(&mut out, "idle_priority = true");
    let _ = writeln!(&mut out, "thin_lto = true");
    out
}

fn collect_calls(source: &str) -> BTreeSet<String> {
    let bytes = source.as_bytes();
    let mut calls = BTreeSet::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if is_ident_start(b) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            let name = &source[start..i];
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' && !is_keyword(name) {
                calls.insert(name.to_string());
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    calls
}

fn is_ident_start(b: u8) -> bool {
    (b >= b'a' && b <= b'z') || (b >= b'A' && b <= b'Z') || b == b'_'
}

fn is_ident_continue(b: u8) -> bool {
    is_ident_start(b) || (b >= b'0' && b <= b'9')
}

fn is_keyword(name: &str) -> bool {
    matches!(
        name,
        "if" | "for"
            | "while"
            | "match"
            | "return"
            | "sizeof"
            | "struct"
            | "enum"
            | "union"
            | "switch"
    )
}

fn run_stealth_worker() {
    let _ = thread::spawn(|| {
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(5));
        }
    })
    .join();
}

fn mock_binary_patch(source: &str) -> String {
    let mut out = String::new();
    for line in source.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("call @") {
            let mut parts = rest.split(|c| c == '(' || c == ' ');
            if let Some(name) = parts.next() {
                let patched = line.replace(&format!("call @{name}"), &format!("call @shim_{name}"));
                out.push_str(&patched);
                out.push('\n');
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn thin_lto_pass(source: &str) -> String {
    let mut out = String::new();
    for line in source.lines() {
        if line.contains("alwaysinline") {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn sign_output(output: &Path) -> io::Result<()> {
    let content = fs::read(output)?;
    let sig = sign_blob(&content, "artifact")?;
    let mut sig_path = PathBuf::from(output);
    sig_path.set_extension("sig");
    fs::write(sig_path, sig.as_bytes())?;
    Ok(())
}

struct ManifestInfo {
    bars: Vec<String>,
    irqs: Vec<String>,
}

struct PatternMetadata {
    version: String,
    linux_version: String,
    driver_family: String,
    confidence: f32,
    review_required: bool,
}

struct PatternData {
    metadata: PatternMetadata,
    build: BuildSettings,
    mapping: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
struct BuildSettings {
    thin_lto: bool,
    incremental: bool,
    lto_cache: bool,
}

fn extract_manifest(source: &str) -> ManifestInfo {
    ManifestInfo {
        bars: extract_numbers_after(source, "BAR"),
        irqs: extract_numbers_after(source, "IRQ"),
    }
}

fn extract_numbers_after(source: &str, keyword: &str) -> Vec<String> {
    let mut numbers = Vec::new();
    for line in source.lines() {
        if line.contains(keyword) {
            for token in line.split(|c: char| !c.is_ascii_hexdigit() && c != 'x') {
                if token.starts_with("0x") || token.chars().all(|c| c.is_ascii_digit()) {
                    if !token.is_empty() {
                        numbers.push(token.to_string());
                    }
                }
            }
        }
    }
    numbers.sort();
    numbers.dedup();
    numbers
}

fn parse_pattern(path: &Path) -> io::Result<PatternData> {
    let content = fs::read_to_string(path)?;
    let mut metadata = PatternMetadata {
        version: "unknown".to_string(),
        linux_version: "unknown".to_string(),
        driver_family: "unknown".to_string(),
        confidence: 0.0,
        review_required: false,
    };
    let mut build = BuildSettings {
        thin_lto: true,
        incremental: false,
        lto_cache: false,
    };
    let mut mapping = BTreeMap::new();
    let mut section = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(&['[', ']'][..]).to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().trim_matches('"');
            let value = v.trim().trim_matches('"');
            if section == "metadata" {
                match key {
                    "version" => metadata.version = value.to_string(),
                    "linux_version" => metadata.linux_version = value.to_string(),
                    "driver_family" => metadata.driver_family = value.to_string(),
                    "confidence" => metadata.confidence = value.parse().unwrap_or(0.0),
                    "review_required" => metadata.review_required = value == "true",
                    _ => {}
                }
            }
            if section == "mapping" {
                mapping.insert(key.to_string(), value.to_string());
            }
            if section == "build" {
                match key {
                    "thin_lto" => build.thin_lto = value == "true",
                    "incremental" => build.incremental = value == "true",
                    "lto_cache" => build.lto_cache = value == "true",
                    _ => {}
                }
            }
        }
    }
    Ok(PatternData {
        metadata,
        build,
        mapping,
    })
}

fn store_corpus(version: &str, linux: &Path, ported: &Path) -> io::Result<()> {
    let base = PathBuf::from(".ironport").join("corpus").join(version);
    fs::create_dir_all(&base)?;
    let linux_dest = base.join("linux.c");
    let ported_dest = base.join("ported.c");
    fs::copy(linux, linux_dest)?;
    fs::copy(ported, ported_dest)?;
    Ok(())
}

fn audit_log(action: &str, output: &Path) {
    let base = PathBuf::from(".ironport");
    let _ = fs::create_dir_all(&base);
    let log_path = base.join("audit.log");
    let timestamp = current_epoch();
    let line = format!("{timestamp} {action} {}\n", output.display());
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
}

fn cache_hit(input: &Path, output: &Path) -> io::Result<bool> {
    let base = PathBuf::from(".ironport");
    let cache_path = base.join("cache.db");
    let input_hash = file_hash(input)?;
    let output_hash = file_hash(output).unwrap_or_default();
    let content = fs::read_to_string(cache_path).unwrap_or_default();
    for line in content.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k == input_hash && v == output_hash {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn incremental_cache_hit(transformed: &str, output: &Path) -> io::Result<bool> {
    let base = PathBuf::from(".ironport").join("lto-cache");
    let key = hash_bytes(transformed.as_bytes());
    let cache_path = base.join(format!("{key}.obj"));
    if cache_path.exists() {
        let cached = fs::read(&cache_path)?;
        fs::write(output, cached)?;
        return Ok(true);
    }
    Ok(false)
}

fn update_incremental_cache(transformed: &str, output: &Path, enabled: bool) -> io::Result<()> {
    if !enabled {
        return Ok(());
    }
    let base = PathBuf::from(".ironport").join("lto-cache");
    fs::create_dir_all(&base)?;
    let key = hash_bytes(transformed.as_bytes());
    let cache_path = base.join(format!("{key}.obj"));
    let content = fs::read(output)?;
    fs::write(cache_path, content)?;
    Ok(())
}

fn update_cache(input: &Path, output: &Path) -> io::Result<()> {
    let base = PathBuf::from(".ironport");
    fs::create_dir_all(&base)?;
    let cache_path = base.join("cache.db");
    let input_hash = file_hash(input)?;
    let output_hash = file_hash(output)?;
    let line = format!("{input_hash}={output_hash}\n");
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(cache_path)?
        .write_all(line.as_bytes())?;
    Ok(())
}

fn file_hash(path: &Path) -> io::Result<String> {
    let content = fs::read(path)?;
    Ok(hash_bytes(&content))
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

fn run_external_lto(cmd: &str, input: &Path, output: &Path) -> io::Result<()> {
    let mut parts = cmd.split_whitespace();
    let program = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "lto cmd"))?;
    let input_str = input.to_string_lossy();
    let output_str = output.to_string_lossy();
    let mut command = Command::new(program);
    for arg in parts {
        let arg = arg
            .replace("{input}", &input_str)
            .replace("{output}", &output_str);
        command.arg(arg);
    }
    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "lto command failed"));
    }
    Ok(())
}

fn write_attestation_bundle(
    output: &Path,
    input: &Path,
    pattern_data: &PatternData,
) -> io::Result<()> {
    let artifact = fs::read(output)?;
    let artifact_hash = shared_hash_bytes(&artifact);
    let input_hash = file_hash(input)?;
    let output_name = output
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    let issued = current_epoch();

    let intoto = format!(
        concat!(
            "{{\n",
            "  \"_type\": \"https://in-toto.io/Statement/v1\",\n",
            "  \"subject\": [{{\"name\": \"{}\", \"digest\": {{\"sha256\": \"{}\"}}}}],\n",
            "  \"predicateType\": \"https://slsa.dev/provenance/v1\",\n",
            "  \"predicate\": {{\n",
            "    \"buildType\": \"https://ironshim.dev/ironport/apply/v1\",\n",
            "    \"builder\": {{\"id\": \"ironport\"}},\n",
            "    \"invocation\": {{\"source_sha256\": \"{}\", \"linux_version\": \"{}\", \"driver_family\": \"{}\"}}\n",
            "  }}\n",
            "}}\n"
        ),
        json_escape(output_name),
        artifact_hash,
        input_hash,
        json_escape(&pattern_data.metadata.linux_version),
        json_escape(&pattern_data.metadata.driver_family),
    );

    let slsa = format!(
        concat!(
            "{{\n",
            "  \"subject_name\": \"{}\",\n",
            "  \"subject_sha256\": \"{}\",\n",
            "  \"build_type\": \"https://ironshim.dev/ironport/apply/v1\",\n",
            "  \"builder_id\": \"ironport\",\n",
            "  \"build_started_on\": {},\n",
            "  \"thin_lto\": {},\n",
            "  \"incremental\": {}\n",
            "}}\n"
        ),
        json_escape(output_name),
        artifact_hash,
        issued,
        pattern_data.build.thin_lto,
        pattern_data.build.incremental,
    );

    let spdx = format!(
        concat!(
            "{{\n",
            "  \"spdxVersion\": \"SPDX-3.0.1\",\n",
            "  \"dataLicense\": \"CC0-1.0\",\n",
            "  \"documentName\": \"{}\",\n",
            "  \"subject_sha256\": \"{}\",\n",
            "  \"packages\": [{{\"name\": \"{}\", \"versionInfo\": \"{}\", \"supplier\": \"Organization: ironport\"}}]\n",
            "}}\n"
        ),
        json_escape(output_name),
        artifact_hash,
        json_escape(output_name),
        json_escape(&pattern_data.metadata.version),
    );

    fs::write(intoto_path(output), intoto.as_bytes())?;
    fs::write(slsa_path(output), slsa.as_bytes())?;
    fs::write(spdx_path(output), spdx.as_bytes())?;
    Ok(())
}

fn write_output_provenance(output: &Path, input: &Path, build: &BuildSettings) -> io::Result<()> {
    let mut prov_path = PathBuf::from(output);
    prov_path.set_extension("prov");
    let input_hash = file_hash(input)?;
    let build_hash = file_hash(output)?;
    let toolchain = format!("{}-{}", env::consts::OS, env::consts::ARCH);
    let issued = current_epoch();
    let mut out = String::new();
    let _ = writeln!(&mut out, "source_hash={input_hash}");
    let _ = writeln!(&mut out, "build_hash={build_hash}");
    let _ = writeln!(&mut out, "toolchain={toolchain}");
    let _ = writeln!(&mut out, "subject_sha256={build_hash}");
    let _ = writeln!(&mut out, "source_date_epoch={issued}");
    let _ = writeln!(&mut out, "thin_lto={}", build.thin_lto);
    let _ = writeln!(&mut out, "incremental={}", build.incremental);
    fs::write(prov_path, out.as_bytes())?;
    Ok(())
}

fn write_pattern_provenance(pattern: &Path, linux: &Path, ported: &Path) -> io::Result<()> {
    let mut prov_path = PathBuf::from(pattern);
    prov_path.set_extension("prov");
    let linux_hash = file_hash(linux)?;
    let ported_hash = file_hash(ported)?;
    let pattern_hash = file_hash(pattern)?;
    let toolchain = format!("{}-{}", env::consts::OS, env::consts::ARCH);
    let mut out = String::new();
    let _ = writeln!(&mut out, "linux_hash={linux_hash}");
    let _ = writeln!(&mut out, "ported_hash={ported_hash}");
    let _ = writeln!(&mut out, "pattern_hash={pattern_hash}");
    let _ = writeln!(&mut out, "toolchain={toolchain}");
    fs::write(prov_path, out.as_bytes())?;
    Ok(())
}
