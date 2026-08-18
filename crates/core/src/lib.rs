//! Núcleo defensivo do Allan Security.
//!
//! O núcleo nunca executa os arquivos analisados. Ele apenas lê metadados e bytes,
//! calcula hashes, consulta assinaturas, aplica regras YARA e registra ações explícitas.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use reqwest::blocking::Client;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use yara_x::{Compiler, Scanner};

pub const APP_NAME: &str = "Allan Security";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const EICAR_TEST_STRING: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
pub const MAX_ANALYSIS_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRecord {
    pub sha256: String,
    pub name: String,
    pub family: String,
    pub category: String,
    pub severity: Severity,
    pub signature_version: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub path: PathBuf,
    pub sha256: String,
    pub file_size: u64,
    pub severity: Severity,
    pub signature_match: Option<ThreatRecord>,
    pub yara_matches: Vec<String>,
    pub heuristic_score: u32,
    pub reasons: Vec<String>,
}

impl DetectionResult {
    pub fn is_threat(&self) -> bool {
        !matches!(self.severity, Severity::Clean)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    pub scanned_files: u64,
    pub threats_found: u64,
    pub errors: u64,
    pub detections: Vec<DetectionResult>,
    pub elapsed_ms: u128,
}

pub struct SignatureDatabase {
    connection: Connection,
}

impl SignatureDatabase {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("criando {}", parent.display()))?;
        }
        let connection =
            Connection::open(path).with_context(|| format!("abrindo {}", path.display()))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS threat_signatures (
                 sha256 TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 family TEXT NOT NULL,
                 category TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 signature_version TEXT NOT NULL,
                 source TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_threat_family ON threat_signatures(family);
             CREATE INDEX IF NOT EXISTS idx_threat_category ON threat_signatures(category);",
        )?;
        Ok(Self { connection })
    }

    pub fn add(&self, record: &ThreatRecord) -> Result<()> {
        self.connection.execute(
            "INSERT OR REPLACE INTO threat_signatures
             (sha256, name, family, category, severity, signature_version, source, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.sha256,
                record.name,
                record.family,
                record.category,
                record.severity.as_str(),
                record.signature_version,
                record.source,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn lookup(&self, sha256: &str) -> Result<Option<ThreatRecord>> {
        self.connection
            .query_row(
                "SELECT sha256, name, family, category, severity, signature_version, source
                 FROM threat_signatures WHERE sha256 = ?1",
                params![sha256],
                |row| {
                    let severity: String = row.get(4)?;
                    Ok(ThreatRecord {
                        sha256: row.get(0)?,
                        name: row.get(1)?,
                        family: row.get(2)?,
                        category: row.get(3)?,
                        severity: parse_severity(&severity),
                        signature_version: row.get(5)?,
                        source: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }
}

fn parse_severity(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Clean,
    }
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn download_bytes(url: &str) -> Result<Vec<u8>> {
    let client = Client::builder()
        .user_agent(format!("{APP_NAME}/{VERSION}"))
        .build()?;
    let mut response = client.get(url).send()?.error_for_status()?;
    let mut bytes = Vec::new();
    response.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("abrindo {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub struct YaraEngine {
    rules: yara_x::Rules,
    pub invalid_rules: Vec<String>,
}

impl YaraEngine {
    pub fn from_dir(dir: &Path) -> Result<Self> {
        let mut compiler = Compiler::new();
        compiler.enable_includes(false);
        compiler.error_on_slow_pattern(true);
        let mut invalid_rules = Vec::new();

        if dir.exists() {
            for entry in collect_files(dir)? {
                let extension = entry
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or_default();
                if !matches!(extension.to_ascii_lowercase().as_str(), "yar" | "yara") {
                    continue;
                }
                match fs::read_to_string(&entry) {
                    Ok(source) => {
                        if let Err(error) = compiler.add_source(source.as_str()) {
                            invalid_rules.push(format!("{}: {}", entry.display(), error));
                        }
                    }
                    Err(error) => invalid_rules.push(format!("{}: {}", entry.display(), error)),
                }
            }
        }

        Ok(Self {
            rules: compiler.build(),
            invalid_rules,
        })
    }

    pub fn scan_bytes(&self, bytes: &[u8]) -> Result<Vec<String>> {
        let mut scanner = Scanner::new(&self.rules);
        scanner
            .set_timeout(Duration::from_secs(5))
            .use_mmap(false)
            .max_scan_size(MAX_ANALYSIS_BYTES as usize);
        let results = scanner
            .scan(bytes)
            .map_err(|error| anyhow!("YARA: {error}"))?;
        Ok(results
            .matching_rules()
            .map(|rule| rule.identifier().to_string())
            .collect())
    }
}

pub struct QuarantineManager {
    root: PathBuf,
}

impl QuarantineManager {
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn quarantine(&self, path: &Path, sha256: &str) -> Result<PathBuf> {
        let source =
            fs::canonicalize(path).with_context(|| format!("validando {}", path.display()))?;
        let file_name = source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("item");
        let destination = self.root.join(format!(
            "{}-{}.quarantined",
            &sha256[..16.min(sha256.len())],
            file_name
        ));
        fs::copy(&source, &destination)
            .with_context(|| format!("copiando para {}", destination.display()))?;
        let metadata = serde_json::json!({
            "original_path": source,
            "sha256": sha256,
            "quarantined_at": Utc::now().to_rfc3339(),
        });
        let sidecar = destination.with_extension("json");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&sidecar)?;
        file.write_all(serde_json::to_string_pretty(&metadata)?.as_bytes())?;
        fs::remove_file(&source)
            .with_context(|| format!("removendo original {}", source.display()))?;
        Ok(destination)
    }

    pub fn list(&self) -> Result<Vec<PathBuf>> {
        Ok(fs::read_dir(&self.root)?
            .filter_map(|entry| entry.ok().map(|item| item.path()))
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("quarantined"))
            .collect())
    }
}

pub struct ScanEngine {
    signatures: SignatureDatabase,
    yara: YaraEngine,
}

impl ScanEngine {
    pub fn new(signatures: SignatureDatabase, yara: YaraEngine) -> Self {
        Self { signatures, yara }
    }

    pub fn scan_path(&self, path: &Path) -> Result<ScanSummary> {
        let started = Instant::now();
        let mut summary = ScanSummary::default();
        let files = if path.is_dir() {
            collect_files(path)?
        } else if path.is_file() {
            vec![path.to_path_buf()]
        } else {
            return Err(anyhow!("caminho não encontrado: {}", path.display()));
        };

        for file in files {
            match self.scan_file(&file) {
                Ok(Some(detection)) => {
                    summary.threats_found += 1;
                    summary.detections.push(detection);
                    summary.scanned_files += 1;
                }
                Ok(None) => summary.scanned_files += 1,
                Err(_) => summary.errors += 1,
            }
        }
        summary.elapsed_ms = started.elapsed().as_millis();
        Ok(summary)
    }

    fn scan_file(&self, path: &Path) -> Result<Option<DetectionResult>> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() || metadata.len() > MAX_ANALYSIS_BYTES {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        self.scan_bytes(path, metadata.len(), &bytes)
    }

    fn scan_bytes(
        &self,
        path: &Path,
        file_size: u64,
        bytes: &[u8],
    ) -> Result<Option<DetectionResult>> {
        let sha256 = sha256_bytes(bytes);
        let signature_match = self.signatures.lookup(&sha256)?;
        let yara_matches = self.yara.scan_bytes(bytes)?;
        let mut reasons = Vec::new();
        let mut heuristic_score = 0;

        if bytes
            .windows(EICAR_TEST_STRING.len())
            .any(|window| window == EICAR_TEST_STRING.as_bytes())
        {
            reasons.push("EICAR test signature encontrada".to_string());
            heuristic_score += 100;
        }
        if signature_match.is_some() {
            reasons.push("hash SHA-256 presente no banco local de assinaturas".to_string());
        }
        if !yara_matches.is_empty() {
            reasons.push(format!(
                "{} regra(s) YARA correspondida(s)",
                yara_matches.len()
            ));
        }

        let severity = signature_match
            .as_ref()
            .map(|record| record.severity.clone())
            .unwrap_or_else(|| {
                if heuristic_score >= 100 || !yara_matches.is_empty() {
                    Severity::High
                } else {
                    Severity::Clean
                }
            });

        if matches!(severity, Severity::Clean) {
            return Ok(None);
        }
        Ok(Some(DetectionResult {
            path: path.to_path_buf(),
            sha256,
            file_size,
            severity,
            signature_match,
            yara_matches,
            heuristic_score,
            reasons,
        }))
    }
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                files.push(path);
            }
        }
    }
    Ok(files)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub prerelease: bool,
    pub draft: bool,
    pub assets: Vec<GitHubAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    pub repository: String,
    pub assets: Vec<ReleaseManifestAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifestAsset {
    pub name: String,
    pub sha256: String,
}

pub fn latest_release(repo: &str) -> Result<GitHubRelease> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let client = Client::builder()
        .user_agent(format!("{APP_NAME}/{VERSION}"))
        .build()?;
    let response = client.get(url).send()?.error_for_status()?;
    Ok(response.json()?)
}

pub fn release_is_newer(tag: &str) -> bool {
    let remote = tag.trim_start_matches('v');
    let Ok(remote) = semver::Version::parse(remote) else {
        return false;
    };
    let Ok(local) = semver::Version::parse(VERSION) else {
        return false;
    };
    remote > local
}

pub fn download_verified(url: &str, destination: &Path, expected_sha256: &str) -> Result<()> {
    let client = Client::builder()
        .user_agent(format!("{APP_NAME}/{VERSION}"))
        .build()?;
    let mut response = client.get(url).send()?.error_for_status()?;
    let temporary = destination.with_extension("download");
    let mut output = File::create(&temporary)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = response.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    output.flush()?;
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_sha256.trim_start_matches("sha256:")) {
        let _ = fs::remove_file(&temporary);
        return Err(anyhow!(
            "hash SHA-256 divergente: esperado {expected_sha256}, recebido {actual}"
        ));
    }
    if destination.exists() {
        let backup = destination.with_extension("previous");
        let _ = fs::remove_file(&backup);
        fs::rename(destination, &backup)?;
    }
    fs::rename(&temporary, destination)?;
    Ok(())
}

pub fn default_data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data"))
        .join("AllanSecurity")
}

pub fn seed_demo_signatures(database: &SignatureDatabase) -> Result<()> {
    let mut demo_hasher = Sha256::new();
    demo_hasher.update(EICAR_TEST_STRING.as_bytes());
    let record = ThreatRecord {
        sha256: hex::encode(demo_hasher.finalize()),
        name: "EICAR-Test-File".to_string(),
        family: "Test".to_string(),
        category: "antivirus-test".to_string(),
        severity: Severity::Critical,
        signature_version: "builtin-0.1".to_string(),
        source: "EICAR test standard".to_string(),
    };
    database.add(&record)
}

pub fn unique_reasons(result: &DetectionResult) -> Vec<String> {
    result
        .reasons
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sha256_is_stable() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("sample.bin");
        fs::write(&file, b"abc").unwrap();
        assert_eq!(
            sha256_file(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn eicar_is_detected_by_engine() {
        let dir = tempdir().unwrap();
        let db = SignatureDatabase::open(&dir.path().join("signatures.db")).unwrap();
        seed_demo_signatures(&db).unwrap();
        let rules = dir.path().join("rules");
        fs::create_dir_all(&rules).unwrap();
        fs::write(rules.join("eicar.yar"), r#"rule EICAR_String { strings: $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $eicar }"#).unwrap();
        let engine = ScanEngine::new(db, YaraEngine::from_dir(&rules).unwrap());
        let sample = dir.path().join("eicar.com");
        let detection = engine
            .scan_bytes(
                &sample,
                EICAR_TEST_STRING.len() as u64,
                EICAR_TEST_STRING.as_bytes(),
            )
            .unwrap()
            .expect("EICAR deve ser detectado em memória");
        assert!(detection.is_threat());
        assert!(detection
            .yara_matches
            .iter()
            .any(|name| name == "EICAR_String"));
    }

    #[test]
    fn invalid_rule_does_not_break_engine() {
        let dir = tempdir().unwrap();
        let rules = dir.path().join("rules");
        fs::create_dir_all(&rules).unwrap();
        fs::write(rules.join("bad.yar"), "rule broken { condition: }").unwrap();
        let engine = YaraEngine::from_dir(&rules).unwrap();
        assert_eq!(engine.scan_bytes(b"safe").unwrap().len(), 0);
        assert_eq!(engine.invalid_rules.len(), 1);
    }
}
