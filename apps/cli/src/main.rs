use allan_core::{
    default_data_dir, latest_release, release_is_newer, seed_demo_signatures, unique_reasons,
    QuarantineManager, ScanEngine, SignatureDatabase, YaraEngine, EICAR_TEST_STRING, VERSION,
};
use anyhow::{anyhow, Context, Result};
use std::{
    env, fs,
    path::{Path, PathBuf},
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
            let mut paths = Vec::new();
            if let Some(profile) = env::var_os("USERPROFILE") {
                let profile = PathBuf::from(profile);
                paths.push(profile.join("Downloads"));
                paths.push(profile.join("Desktop"));
            }
            if let Some(temp) = env::var_os("TEMP") {
                paths.push(PathBuf::from(temp));
            }
            for path in paths.into_iter().filter(|path| path.exists()) {
                println!("Verificando {}", path.display());
                let summary = build_engine()?.scan_path(&path)?;
                print_summary(&summary, false)?;
            }
        }
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
        "quarantine" => {
            let path = args
                .next()
                .ok_or_else(|| anyhow!("uso: allan-security-cli quarantine <arquivo>"))?;
            let db = SignatureDatabase::open(&default_data_dir().join("signatures.db"))?;
            let sha256 = allan_core::sha256_file(Path::new(&path))?;
            let quarantine = QuarantineManager::new(default_data_dir().join("quarantine"))?;
            let destination = quarantine.quarantine(Path::new(&path), &sha256)?;
            println!("Arquivo movido para quarentena: {}", destination.display());
            drop(db);
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
    Ok(ScanEngine::new(db, yara))
}

fn print_summary(summary: &allan_core::ScanSummary, json: bool) -> Result<()> {
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
    println!("  scan <arquivo-ou-pasta> [--json]  Verificação personalizada");
    println!("  quick-scan                        Downloads, Desktop e temporários");
    println!("  eicar                             Criar arquivo de teste EICAR sem executar");
    println!("  quarantine <arquivo>              Mover arquivo confirmado para quarentena");
    println!("  check-update [owner/repo]         Consultar a última GitHub Release");
    println!("  version                           Exibir a versão");
}
