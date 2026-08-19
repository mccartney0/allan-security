use crate::{default_data_dir, policy::ExclusionPolicy, ScanEngine, ScanSummary};
use anyhow::{anyhow, Context, Result};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct RealtimeConfig {
    pub paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
    pub policy: ExclusionPolicy,
    pub debounce: Duration,
    pub stability_window: Duration,
    pub stability_attempts: u8,
    pub max_pending_paths: usize,
    pub history_path: Option<PathBuf>,
}

impl RealtimeConfig {
    pub fn quick_paths() -> Self {
        let mut paths = Vec::new();
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            let profile = PathBuf::from(profile);
            paths.push(profile.join("Downloads"));
            paths.push(profile.join("Desktop"));
        }
        let data_dir = default_data_dir();
        let policy = ExclusionPolicy::load_default().unwrap_or_default();
        Self {
            paths,
            excluded_paths: vec![data_dir.join("quarantine"), data_dir.join("history.jsonl")],
            policy,
            debounce: Duration::from_millis(600),
            stability_window: Duration::from_millis(250),
            stability_attempts: 8,
            max_pending_paths: 512,
            history_path: Some(data_dir.join("history.jsonl")),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.paths.is_empty() {
            return Err(anyhow!(
                "nenhum diretório de proteção em tempo real foi configurado"
            ));
        }
        if self.max_pending_paths == 0 {
            return Err(anyhow!("max_pending_paths precisa ser maior que zero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RealtimeNotification {
    pub path: PathBuf,
    pub action: String,
    pub summary: ScanSummary,
    pub error: Option<String>,
}

impl RealtimeNotification {
    fn warning(message: impl Into<String>) -> Self {
        Self {
            path: PathBuf::new(),
            action: "warning".to_string(),
            summary: ScanSummary::default(),
            error: Some(message.into()),
        }
    }
}

pub struct RealtimeMonitor {
    engine: ScanEngine,
    config: RealtimeConfig,
}

impl RealtimeMonitor {
    pub fn new(engine: ScanEngine, config: RealtimeConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { engine, config })
    }

    pub fn run_blocking<F>(&mut self, stop: Arc<AtomicBool>, mut callback: F) -> Result<()>
    where
        F: FnMut(RealtimeNotification),
    {
        let (event_tx, event_rx) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher = RecommendedWatcher::new(
            move |result| {
                let _ = event_tx.send(result);
            },
            Config::default(),
        )
        .context("criando watcher de filesystem")?;

        let mut watched = 0;
        for path in &self.config.paths {
            if !path.exists() {
                callback(RealtimeNotification::warning(format!(
                    "diretório ausente: {}",
                    path.display()
                )));
                continue;
            }
            watcher
                .watch(path, RecursiveMode::Recursive)
                .with_context(|| format!("observando {}", path.display()))?;
            watched += 1;
        }
        if watched == 0 {
            return Err(anyhow!("nenhum diretório configurado pôde ser observado"));
        }

        let mut pending = BTreeSet::new();
        let mut last_event = Instant::now();
        while !stop.load(Ordering::Acquire) {
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Ok(event)) => {
                    if !is_relevant_event(&event.kind) {
                        continue;
                    }
                    for path in event.paths {
                        if self.is_internal_excluded(&path) || !is_candidate(&path) {
                            continue;
                        }
                        if pending.len() >= self.config.max_pending_paths {
                            pending.clear();
                            callback(RealtimeNotification::warning("fila de proteção em tempo real excedeu o limite; eventos pendentes foram descartados e a próxima alteração será observada"));
                        }
                        pending.insert(path);
                    }
                    last_event = Instant::now();
                }
                Ok(Err(error)) => {
                    callback(RealtimeNotification::warning(format!("notificação de filesystem indisponível: {error}; alterações futuras continuarão sendo observadas quando possível")));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if !pending.is_empty() && last_event.elapsed() >= self.config.debounce {
                        let paths = std::mem::take(&mut pending);
                        for path in paths {
                            if stop.load(Ordering::Acquire) {
                                break;
                            }
                            callback(self.scan_stable_path(&path));
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        Ok(())
    }

    fn scan_stable_path(&self, path: &Path) -> RealtimeNotification {
        if !wait_until_stable(
            path,
            self.config.stability_window,
            self.config.stability_attempts,
        ) {
            return RealtimeNotification {
                path: path.to_path_buf(),
                action: "deferred".to_string(),
                summary: ScanSummary::default(),
                error: Some(
                    "arquivo ainda estava sendo escrito; nenhuma ação foi aplicada".to_string(),
                ),
            };
        }
        match self.engine.scan_path(path) {
            Ok(summary) => {
                append_history(self.config.history_path.as_deref(), path, &summary);
                RealtimeNotification {
                    path: path.to_path_buf(),
                    action: "scan".to_string(),
                    summary,
                    error: None,
                }
            }
            Err(error) => RealtimeNotification {
                path: path.to_path_buf(),
                action: "error".to_string(),
                summary: ScanSummary::default(),
                error: Some(error.to_string()),
            },
        }
    }

    fn is_internal_excluded(&self, path: &Path) -> bool {
        self.config
            .excluded_paths
            .iter()
            .any(|excluded| path == excluded || path.starts_with(excluded))
    }
}

fn is_relevant_event(kind: &EventKind) -> bool {
    matches!(kind, EventKind::Create(_) | EventKind::Modify(_))
}

fn is_candidate(path: &Path) -> bool {
    path.is_file() || path.extension().is_some()
}

fn wait_until_stable(path: &Path, interval: Duration, attempts: u8) -> bool {
    let Ok(first) = fs::metadata(path) else {
        return false;
    };
    let mut previous = (first.len(), first.modified().ok());
    for _ in 0..attempts.max(1) {
        thread::sleep(interval);
        let Ok(current) = fs::metadata(path) else {
            return false;
        };
        let state = (current.len(), current.modified().ok());
        if state == previous {
            return true;
        }
        previous = state;
    }
    false
}

fn append_history(history_path: Option<&Path>, target: &Path, summary: &ScanSummary) {
    let Some(history_path) = history_path else {
        return;
    };
    let action = if summary.threats_found > 0 {
        crate::HistoryAction::ThreatDetected
    } else {
        crate::HistoryAction::ScanCompleted
    };
    let _ = crate::append_history_record(
        history_path,
        crate::HistorySource::Realtime,
        action,
        Some(target),
        Some(summary),
        None,
    );
}
