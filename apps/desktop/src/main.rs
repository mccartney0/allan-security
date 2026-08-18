use allan_core::{
    default_data_dir, latest_release, release_is_newer, seed_demo_signatures, DetectionResult,
    QuarantineManager, ScanEngine, ScanSummary, SignatureDatabase, YaraEngine, APP_NAME, VERSION,
};
use eframe::egui;
use rfd::FileDialog;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::Duration,
};

const REPOSITORY: &str = "mccartney0/allan-security";
const DESKTOP_ASSET: &str = "allan-security-desktop-x86_64-pc-windows-msvc.exe";
const CLI_ASSET: &str = "allan-security-cli-x86_64-pc-windows-msvc.exe";

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 680.0])
            .with_min_inner_size([760.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|_cc| Ok(Box::new(AllanApp::new()))),
    )
}

struct AllanApp {
    engine: Option<ScanEngine>,
    quarantine: Option<QuarantineManager>,
    selected_path: Option<PathBuf>,
    summary: Option<ScanSummary>,
    status: String,
    latest_release: Option<String>,
    update_message: String,
    update_available: bool,
    realtime_child: Option<Child>,
    realtime_message: String,
}

impl AllanApp {
    fn new() -> Self {
        let data_dir = default_data_dir();
        let (engine, status) = match Self::build_engine() {
            Ok(engine) => (
                Some(engine),
                "Protegido — pronto para verificar".to_string(),
            ),
            Err(error) => (None, format!("Inicialização limitada: {error}")),
        };
        let quarantine = QuarantineManager::new(data_dir.join("quarantine")).ok();
        Self {
            engine,
            quarantine,
            selected_path: None,
            summary: None,
            status,
            latest_release: None,
            update_message: String::new(),
            update_available: false,
            realtime_child: None,
            realtime_message: String::new(),
        }
    }

    fn build_engine() -> anyhow::Result<ScanEngine> {
        let data_dir = default_data_dir();
        let db = SignatureDatabase::open(&data_dir.join("signatures.db"))?;
        seed_demo_signatures(&db)?;
        let rules_dir = env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|parent| parent.join("rules")))
            .filter(|path| path.exists())
            .unwrap_or_else(|| PathBuf::from("rules"));
        let yara = YaraEngine::from_dir(&rules_dir)?;
        let warnings = yara.invalid_rules.len();
        let mut engine = ScanEngine::new(db, yara);
        if warnings > 0 {
            // A regra inválida é isolada pelo carregador; o dashboard continua operacional.
            let _ = &mut engine;
        }
        Ok(engine)
    }

    fn scan(&mut self, path: PathBuf) {
        self.selected_path = Some(path.clone());
        self.status = format!("Verificando {}", path.display());
        match self
            .engine
            .as_ref()
            .and_then(|engine| engine.scan_path(&path).ok())
        {
            Some(summary) => {
                self.status = if summary.threats_found == 0 {
                    "Verificação concluída — nenhum sinal detectado".to_string()
                } else {
                    format!(
                        "Verificação concluída — {} ameaça(s) para ação",
                        summary.threats_found
                    )
                };
                self.persist_history(&summary);
                self.summary = Some(summary);
            }
            None => {
                self.status = "Não foi possível iniciar o scanner; consulte o log local".to_string()
            }
        }
    }

    fn quick_scan(&mut self) {
        let mut candidates = Vec::new();
        if let Some(profile) = env::var_os("USERPROFILE") {
            let profile = PathBuf::from(profile);
            candidates.push(profile.join("Downloads"));
            candidates.push(profile.join("Desktop"));
        }
        if let Some(temp) = env::var_os("TEMP") {
            candidates.push(PathBuf::from(temp));
        }
        let existing: Vec<_> = candidates
            .into_iter()
            .filter(|path| path.exists())
            .collect();
        let mut combined = ScanSummary::default();
        for path in existing {
            if let Some(engine) = &self.engine {
                if let Ok(summary) = engine.scan_path(&path) {
                    combined.scanned_files += summary.scanned_files;
                    combined.threats_found += summary.threats_found;
                    combined.errors += summary.errors;
                    combined.elapsed_ms += summary.elapsed_ms;
                    combined.detections.extend(summary.detections);
                }
            }
        }
        self.status = format!(
            "Quick Scan concluído — {} arquivo(s), {} ameaça(s)",
            combined.scanned_files, combined.threats_found
        );
        self.persist_history(&combined);
        self.summary = Some(combined);
        self.selected_path = None;
    }

    fn persist_history(&self, summary: &ScanSummary) {
        if let Ok(serialized) = serde_json::to_string(summary) {
            let path = default_data_dir().join("history.jsonl");
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut file| {
                    std::io::Write::write_all(&mut file, format!("{serialized}\n").as_bytes())
                });
        }
    }

    fn check_updates(&mut self) {
        match latest_release(REPOSITORY) {
            Ok(release) => {
                self.update_available = release_is_newer(&release.tag_name);
                self.latest_release = Some(release.tag_name.clone());
                self.update_message = if self.update_available {
                    format!("Nova versão disponível: {}", release.tag_name)
                } else {
                    format!("Você já está usando a versão {}", VERSION)
                };
            }
            Err(error) => {
                self.update_message = format!("Não foi possível consultar Releases: {error}")
            }
        }
    }

    fn realtime_cli_path() -> Option<PathBuf> {
        let parent = env::current_exe().ok()?.parent()?.to_path_buf();
        [CLI_ASSET, "allan-security-cli.exe"]
            .iter()
            .map(|name| parent.join(name))
            .find(|path| path.exists())
    }

    fn toggle_realtime(&mut self) {
        if let Some(mut child) = self.realtime_child.take() {
            let _ = child.kill();
            let _ = child.wait();
            self.realtime_message = "Proteção em tempo real desativada".to_string();
            self.status = "Protegido — monitoramento em tempo real desligado".to_string();
            return;
        }
        let Some(cli) = Self::realtime_cli_path() else {
            self.realtime_message =
                "CLI de monitoramento não encontrado ao lado do desktop".to_string();
            return;
        };
        match Command::new(cli).arg("realtime").spawn() {
            Ok(child) => {
                self.realtime_child = Some(child);
                self.realtime_message =
                    "Proteção em tempo real ativada para Downloads e Desktop".to_string();
                self.status = "Protegido — monitoramento em tempo real ativo".to_string();
            }
            Err(error) => {
                self.realtime_message = format!("Falha ao iniciar proteção em tempo real: {error}")
            }
        }
    }

    fn poll_realtime(&mut self) {
        let result = self.realtime_child.as_mut().map(|child| child.try_wait());
        if let Some(Ok(Some(status))) = result {
            self.realtime_child = None;
            self.realtime_message = format!("Monitoramento encerrado ({status})");
            self.status = "Protegido — monitoramento em tempo real desligado".to_string();
        }
    }

    fn launch_update(&mut self, ctx: &egui::Context) {
        let Ok(current_exe) = env::current_exe() else {
            self.update_message = "Caminho do executável não encontrado".to_string();
            return;
        };
        let Some(parent) = current_exe.parent() else {
            return;
        };
        let updater = parent.join("allan-security-updater.exe");
        if !updater.exists() {
            self.update_message = format!("Atualizador não encontrado em {}", updater.display());
            return;
        }
        let result = Command::new(updater)
            .args(["--repo", REPOSITORY, "--asset", DESKTOP_ASSET, "--target"])
            .arg(&current_exe)
            .arg("--pid")
            .arg(std::process::id().to_string())
            .spawn();
        match result {
            Ok(_) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Err(error) => self.update_message = format!("Falha ao iniciar atualização: {error}"),
        }
    }

    fn quarantine_detections(&mut self) {
        let Some(quarantine) = &self.quarantine else {
            return;
        };
        let Some(summary) = &self.summary else {
            return;
        };
        let mut moved = 0;
        for detection in &summary.detections {
            if quarantine
                .quarantine(&detection.path, &detection.sha256)
                .is_ok()
            {
                moved += 1;
            }
        }
        self.status = format!("{} item(ns) movido(s) para quarentena", moved);
        if moved > 0 {
            self.summary = None;
        }
    }
}

impl eframe::App for AllanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_realtime();
        ctx.request_repaint_after(Duration::from_millis(500));
        let background = egui::Color32::from_rgb(14, 20, 30);
        let panel = egui::Color32::from_rgb(24, 33, 47);
        let accent = egui::Color32::from_rgb(71, 196, 145);
        ctx.set_visuals(egui::Visuals::dark());
        egui::CentralPanel::default().frame(egui::Frame::default().fill(background)).show(ctx, |ui| {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("ALLAN SECURITY").color(accent).size(28.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("v{VERSION}"));
                });
            });
            ui.label("Proteção defensiva local para Windows — os arquivos são analisados sem execução.");
            ui.add_space(14.0);

            egui::Frame::group(ui.style()).fill(panel).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Status do computador").strong());
                    ui.separator();
                    ui.colored_label(accent, "✓");
                    ui.label(&self.status);
                });
                ui.horizontal(|ui| {
                    let active = self.realtime_child.is_some();
                    ui.label("Proteção em tempo real:");
                    ui.colored_label(if active { accent } else { egui::Color32::YELLOW }, if active { "ATIVADA" } else { "DESATIVADA" });
                    if ui.button(if active { "Desativar" } else { "Ativar" }).clicked() { self.toggle_realtime(); }
                });
                ui.label("Modo user-mode: observa Downloads/Desktop sem driver e sem executar arquivos.");
            });
            ui.add_space(12.0);

            ui.horizontal_wrapped(|ui| {
                if ui.button("Verificação rápida").clicked() { self.quick_scan(); }
                if ui.button("Selecionar pasta").clicked() {
                    if let Some(path) = FileDialog::new().pick_folder() { self.scan(path); }
                }
                if ui.button("Selecionar arquivo").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() { self.scan(path); }
                }
                if ui.button("Verificar atualizações").clicked() { self.check_updates(); }
                if self.update_available && ui.button("Atualizar agora").clicked() { self.launch_update(ctx); }
            });
            if !self.update_message.is_empty() { ui.label(&self.update_message); }
            if !self.realtime_message.is_empty() { ui.label(&self.realtime_message); }
            if let Some(path) = &self.selected_path { ui.label(format!("Alvo: {}", path.display())); }
            ui.add_space(12.0);

            let mut quarantine_clicked = false;
            if let Some(summary) = &self.summary {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("Arquivos verificados: {}", summary.scanned_files));
                        ui.separator();
                        ui.label(format!("Ameaças: {}", summary.threats_found));
                        ui.separator();
                        ui.label(format!("Erros: {}", summary.errors));
                        ui.separator();
                        ui.label(format!("Tempo: {} ms", summary.elapsed_ms));
                    });
                    if summary.threats_found > 0 {
                        ui.colored_label(egui::Color32::LIGHT_RED, "Foram encontrados itens que exigem uma ação explícita.");
                        for detection in &summary.detections { render_detection(ui, detection); }
                        if ui.button("Mover detecções para quarentena").clicked() { quarantine_clicked = true; }
                    } else {
                        ui.colored_label(accent, "Nenhum sinal detectado nas áreas verificadas.");
                    }
                });
            } else {
                ui.add_space(20.0);
                ui.centered_and_justified(|ui| {
                    ui.label("Escolha uma verificação para começar. O primeiro marco é selecionar → escanear → detectar → quarentenar → registrar.");
                });
            }
            if quarantine_clicked { self.quarantine_detections(); }
        });
    }
}

fn render_detection(ui: &mut egui::Ui, detection: &DetectionResult) {
    ui.separator();
    ui.colored_label(
        egui::Color32::LIGHT_RED,
        format!(
            "{} — {}",
            detection.severity.as_str().to_uppercase(),
            detection.path.display()
        ),
    );
    ui.label(format!("SHA-256: {}", detection.sha256));
    for reason in &detection.reasons {
        ui.label(format!("Razão: {reason}"));
    }
}

#[allow(dead_code)]
fn _path_exists(path: &Path) -> bool {
    path.exists()
}
