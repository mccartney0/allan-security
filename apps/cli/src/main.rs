use allan_core::cache::ScanCache;
use allan_core::policy::ExclusionPolicy;
use allan_core::realtime::{RealtimeConfig, RealtimeMonitor};
use allan_core::scheduler::{ScanScheduler, ScheduleConfig};
use allan_core::{
    append_history_record, default_data_dir, latest_release, pe, release_is_newer,
    seed_demo_signatures, unique_reasons, HistoryAction, HistorySource, QuarantineManager,
    ScanEngine, ScanSummary, SignatureDatabase, YaraEngine, EICAR_TEST_STRING, VERSION,
};
use anyhow::{anyhow, Context, Result};
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());

    match command.as_str() {
        "scan" => {
            let path = args.next().ok_or_else(|| {
                anyhow!("uso: allan-security-cli scan <arquivo-ou-pasta> [--json]")
            })?;
            let json = args.any(|arg| arg == "--json");
            let summary = build_engine()?.scan_path(Path::new(&path))?;
            print_summary(&summary, json)?;
            if summary.threats_found > 0 {
                std::process::exit(10);
            }
        }
        "quick-scan" => {
            let (paths, json, _) = parse_scan_options(args, quick_scan_paths())?;
            let summary = run_paths(paths, false, json)?;
            if summary.threats_found > 0 {
                std::process::exit(10);
            }
        }
        "full-scan" => {
            let (paths, json, no_cache) = parse_scan_options(args, full_scan_roots())?;
            let summary = run_paths(paths, !no_cache, json)?;
            if summary.threats_found > 0 {
                std::process::exit(10);
            }
        }
        "schedule" => run_schedule(args)?,
        "realtime" => run_realtime(args)?,
        "pe-info" => run_pe_info(args)?,
        "eicar" => {
            let path = env::temp_dir().join("allan-security-eicar.com");
            fs::write(&path, EICAR_TEST_STRING).context("criando arquivo de teste EICAR")?;
            println!(
                "Arquivo EICAR criado para teste defensivo: {}",
                path.display()
            );
            println!(
                "Ele não foi executado. Use `scan {}` para validar a detecção.",
                path.display()
            );
        }
        "exclusions" => exclusions_command(args)?,
        "quarantine" => {
            let path = args
                .next()
                .ok_or_else(|| anyhow!("uso: allan-security-cli quarantine <arquivo>"))?;
            let sha256 = allan_core::sha256_file(Path::new(&path))?;
            let quarantine = QuarantineManager::new(default_data_dir().join("quarantine"))?;
            let destination = quarantine.quarantine(Path::new(&path), &sha256)?;
            println!("Arquivo movido para quarentena: {}", destination.display());
        }
        "quarantine-list" => {
            let quarantine = QuarantineManager::new(default_data_dir().join("quarantine"))?;
            for entry in quarantine.entries()? {
                println!(
                    "{} | {} | {}",
                    entry.sha256,
                    entry.original_path.display(),
                    entry.quarantined_at
                );
            }
        }
        "quarantine-restore" => {
            let path = args.next().ok_or_else(|| {
                anyhow!(
                    "uso: allan-security-cli quarantine-restore <item.quarantined> [--sha256 HASH]"
                )
            })?;
            let mut expected_sha256 = None;
            while let Some(arg) = args.next() {
                if arg == "--sha256" {
                    expected_sha256 = Some(
                        args.next()
                            .ok_or_else(|| anyhow!("--sha256 requer valor"))?,
                    );
                } else {
                    return Err(anyhow!("argumento desconhecido: {arg}"));
                }
            }
            let quarantine = QuarantineManager::new(default_data_dir().join("quarantine"))?;
            let restored = quarantine.restore(Path::new(&path), expected_sha256.as_deref())?;
            println!(
                "Arquivo restaurado por ação explícita: {}",
                restored.display()
            );
        }
        "check-update" => {
            let repo = args
                .next()
                .unwrap_or_else(|| "mccartney0/allan-security".to_string());
            let release = latest_release(&repo)?;
            println!("Versão local: {VERSION}");
            println!("Última Release: {}", release.tag_name);
            println!(
                "Atualização disponível: {}",
                release_is_newer(&release.tag_name)
            );
        }
        "version" | "--version" => println!("{VERSION}"),
        _ => print_help(),
    }
    Ok(())
}

fn build_engine() -> Result<ScanEngine> {
    let data_dir = default_data_dir();
    let db = SignatureDatabase::open(&data_dir.join("signatures.db"))?;
    seed_demo_signatures(&db)?;
    let rules_dir = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("rules")))
        .filter(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from("rules"));
    let yara = YaraEngine::from_dir(&rules_dir)?;
    for warning in &yara.invalid_rules {
        eprintln!("Aviso: regra ignorada com segurança: {warning}");
    }
    let policy = ExclusionPolicy::load_default()?;
    Ok(ScanEngine::new(db, yara).with_policy(policy))
}

fn run_paths(paths: Vec<PathBuf>, use_cache: bool, json: bool) -> Result<ScanSummary> {
    let engine = build_engine()?;
    let mut cache = ScanCache::open(&ScanCache::default_path())?;
    if !use_cache {
        cache.clear()?;
    }
    let engine_key = engine.cache_key();
    let mut combined = ScanSummary::default();
    for path in paths.into_iter().filter(|path| path.exists()) {
        println!("Verificando {}", path.display());
        let summary = if use_cache {
            engine.scan_path_cached(&path, &mut cache, &engine_key)?
        } else {
            engine.scan_path(&path)?
        };
        combined.merge(summary);
    }
    print_summary(&combined, json)?;
    append_history(&combined, HistorySource::Cli);
    Ok(combined)
}

fn parse_scan_options(
    args: impl Iterator<Item = String>,
    defaults: Vec<PathBuf>,
) -> Result<(Vec<PathBuf>, bool, bool)> {
    let mut paths = Vec::new();
    let mut json = false;
    let mut no_cache = false;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--no-cache" => no_cache = true,
            value if value.starts_with("--") => {
                return Err(anyhow!("argumento desconhecido: {value}"))
            }
            value => paths.push(PathBuf::from(value)),
        }
    }
    if paths.is_empty() {
        paths = defaults;
    }
    Ok((paths, json, no_cache))
}

fn run_pe_info(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args
        .next()
        .ok_or_else(|| anyhow!("uso: allan-security-cli pe-info <arquivo> [--json]"))?;
    let json = args.any(|arg| arg == "--json");
    let path = PathBuf::from(path);
    let metadata = fs::metadata(&path).with_context(|| format!("lendo {}", path.display()))?;
    if metadata.len() > pe::MAX_PE_BYTES as u64 {
        return Err(anyhow!(
            "arquivo excede o limite do parser PE ({} bytes)",
            pe::MAX_PE_BYTES
        ));
    }
    let bytes = fs::read(&path).with_context(|| format!("abrindo {}", path.display()))?;
    match pe::analyze_bytes(&bytes)? {
        None => {
            if json {
                println!(
                    "{{\"path\":{},\"status\":\"not-pe\"}}",
                    serde_json::to_string(&path)?
                );
            } else {
                println!("{} não é um PE reconhecido.", path.display());
            }
        }
        Some(report) => {
            pe::validate_report(&report)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("PE: {}", path.display());
                println!("Status: {:?}", report.status);
                println!(
                    "Arquitetura: {} (64-bit: {:?})",
                    report.architecture, report.is_64
                );
                println!("Machine: {:?}", report.machine);
                println!("Timestamp: {:?}", report.timestamp);
                println!("Entry point: {:?}", report.entry_point);
                println!(
                    "Seções: {} | Imports: {}",
                    report.sections.len(),
                    report.imports.len()
                );
                for section in &report.sections {
                    println!(
                        "  seção {} raw={}+{} RVA={} entropia={:?}",
                        section.name,
                        section.raw_offset,
                        section.raw_size,
                        section.address,
                        section.entropy
                    );
                }
                for warning in &report.warnings {
                    println!("Aviso: {warning}");
                }
            }
        }
    }
    Ok(())
}

fn run_schedule(args: impl Iterator<Item = String>) -> Result<()> {
    let mut interval_minutes = 60;
    let mut run_immediately = true;
    let mut paths = Vec::new();
    let mut json = false;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--interval-minutes" => {
                interval_minutes = args
                    .next()
                    .ok_or_else(|| anyhow!("--interval-minutes requer valor"))?
                    .parse()
                    .context("intervalo inválido")?;
            }
            "--no-immediate" => run_immediately = false,
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(anyhow!("argumento desconhecido: {value}"))
            }
            value => paths.push(PathBuf::from(value)),
        }
    }
    if paths.is_empty() {
        paths = quick_scan_paths();
    }
    let mut config = ScheduleConfig::new(paths, interval_minutes);
    config.run_immediately = run_immediately;
    let scheduler = ScanScheduler::new(config)?;
    let engine = build_engine()?;
    let mut cache = ScanCache::open(&ScanCache::default_path())?;
    let stop = install_stop_handler()?;
    println!(
        "Scheduler ativo: a cada {} minuto(s). Pressione Ctrl+C para encerrar.",
        scheduler.config().interval_minutes
    );
    scheduler.run_blocking(&engine, &mut cache, stop, |summary| {
        let _ = print_summary(&summary, json);
        append_history(&summary, HistorySource::Scheduler);
    })?;
    Ok(())
}

fn exclusions_command(mut args: impl Iterator<Item = String>) -> Result<()> {
    let action = args.next().unwrap_or_else(|| "show".to_string());
    let mut policy = ExclusionPolicy::load_default()?;
    match action.as_str() {
        "show" => println!("{}", serde_json::to_string_pretty(&policy)?),
        "add-path" => {
            let path = args
                .next()
                .ok_or_else(|| anyhow!("uso: exclusions add-path <caminho-absoluto>"))?;
            policy.add_path(Path::new(&path))?;
            policy.save_default()?;
            println!("Exclusão de caminho adicionada: {}", path);
        }
        "remove-path" => {
            let path = args
                .next()
                .ok_or_else(|| anyhow!("uso: exclusions remove-path <caminho>"))?;
            if !policy.remove_path(Path::new(&path)) {
                return Err(anyhow!("caminho não estava nas exclusões"));
            }
            policy.save_default()?;
            println!("Exclusão de caminho removida: {}", path);
        }
        "add-ext" => {
            let extension = args
                .next()
                .ok_or_else(|| anyhow!("uso: exclusions add-ext <extensão>"))?;
            policy.add_extension(&extension)?;
            policy.save_default()?;
            println!("Exclusão de extensão adicionada: {}", extension);
        }
        "remove-ext" => {
            let extension = args
                .next()
                .ok_or_else(|| anyhow!("uso: exclusions remove-ext <extensão>"))?;
            if !policy.remove_extension(&extension) {
                return Err(anyhow!("extensão não estava nas exclusões"));
            }
            policy.save_default()?;
            println!("Exclusão de extensão removida: {}", extension);
        }
        value => return Err(anyhow!("ação de exclusões desconhecida: {value}")),
    }
    Ok(())
}

fn run_realtime(args: impl Iterator<Item = String>) -> Result<()> {
    let custom_paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
    let mut config = RealtimeConfig::quick_paths();
    if !custom_paths.is_empty() {
        config.paths = custom_paths;
    }
    let stop = install_stop_handler()?;
    let engine = build_engine()?;
    let mut monitor = RealtimeMonitor::new(engine, config.clone())?;
    println!("Proteção em tempo real iniciada. Diretórios:");
    for path in &config.paths {
        println!("  {}", path.display());
    }
    println!("Pressione Ctrl+C para encerrar de forma limpa.");
    monitor.run_blocking(stop, |notification| {
        if let Some(error) = notification.error {
            eprintln!("[realtime] {}: {}", notification.action, error);
        } else if notification.summary.threats_found > 0 {
            eprintln!(
                "[realtime] ameaça detectada em {}",
                notification.path.display()
            );
            let _ = print_summary(&notification.summary, false);
        } else {
            println!("[realtime] verificado: {}", notification.path.display());
        }
    })?;
    println!("Proteção em tempo real encerrada.");
    Ok(())
}

fn install_stop_handler() -> Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        stop_for_handler.store(true, Ordering::Release);
    })?;
    Ok(stop)
}

fn quick_scan_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(profile) = env::var_os("USERPROFILE") {
        let profile = PathBuf::from(profile);
        paths.push(profile.join("Downloads"));
        paths.push(profile.join("Desktop"));
    }
    if let Some(temp) = env::var_os("TEMP") {
        paths.push(PathBuf::from(temp));
    }
    paths
}

fn full_scan_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for letter in b'A'..=b'Z' {
        let root = PathBuf::from(format!("{}:\\", letter as char));
        if root.exists() {
            roots.push(root);
        }
    }
    if roots.is_empty() {
        roots.push(PathBuf::from("."));
    }
    roots
}

fn append_history(summary: &ScanSummary, source: HistorySource) {
    let action = if summary.threats_found > 0 {
        HistoryAction::ThreatDetected
    } else {
        HistoryAction::ScanCompleted
    };
    let _ = append_history_record(
        &default_data_dir().join("history.jsonl"),
        source,
        action,
        None,
        Some(summary),
        None,
    );
}

fn print_summary(summary: &ScanSummary, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(summary)?);
        return Ok(());
    }
    println!("Arquivos verificados: {}", summary.scanned_files);
    println!("Ameaças encontradas: {}", summary.threats_found);
    println!("Erros de leitura: {}", summary.errors);
    println!("Tempo: {} ms", summary.elapsed_ms);
    for detection in &summary.detections {
        println!(
            "\n[{}] {}",
            detection.severity.as_str().to_uppercase(),
            detection.path.display()
        );
        println!("SHA-256: {}", detection.sha256);
        for reason in unique_reasons(detection) {
            println!("Razão: {reason}");
        }
        println!("Ação: quarentena somente mediante confirmação explícita.");
    }
    Ok(())
}

fn print_help() {
    println!("Allan Security CLI {VERSION}");
    println!("  scan <arquivo-ou-pasta> [--json]  Verificação personalizada sem cache");
    println!("  quick-scan [--json]               Downloads, Desktop e temporários");
    println!("  full-scan [raízes...] [--no-cache] Varredura de volumes com cache por hash/mtime");
    println!("  schedule [--interval-minutes N]   Varredura agendada e contínua");
    println!("  realtime [pastas...]              Monitorar alterações sem executar arquivos");
    println!("  pe-info <arquivo> [--json]        Ler PE estaticamente, sem executar");
    println!("  exclusions show|add-path|remove-path|add-ext|remove-ext");
    println!("  quarantine <arquivo>              Mover arquivo confirmado para quarentena");
    println!("  quarantine-list                   Listar metadados de quarentena");
    println!("  quarantine-restore <item>         Restaurar somente após hash e confirmação");
    println!("  eicar                             Criar arquivo de teste EICAR sem executar");
    println!("  check-update [owner/repo]         Consultar a última GitHub Release");
    println!("  version                           Exibir a versão");
}
