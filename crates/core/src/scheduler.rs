use crate::{cache::ScanCache, ScanEngine, ScanSummary};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduleConfig {
    pub paths: Vec<PathBuf>,
    pub interval_minutes: u64,
    pub run_immediately: bool,
}

impl ScheduleConfig {
    pub fn new(paths: Vec<PathBuf>, interval_minutes: u64) -> Self {
        Self {
            paths,
            interval_minutes,
            run_immediately: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.paths.is_empty() {
            return Err(anyhow!("o scheduler precisa de pelo menos um caminho"));
        }
        if self.interval_minutes == 0 {
            return Err(anyhow!("o intervalo precisa ser maior que zero"));
        }
        Ok(())
    }
}

pub struct ScanScheduler {
    config: ScheduleConfig,
}

impl ScanScheduler {
    pub fn new(config: ScheduleConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &ScheduleConfig {
        &self.config
    }

    pub fn run_once(&self, engine: &ScanEngine, cache: &mut ScanCache) -> Result<ScanSummary> {
        let engine_key = engine.cache_key();
        let mut combined = ScanSummary::default();
        for path in &self.config.paths {
            let summary = engine.scan_path_cached(path, cache, &engine_key)?;
            combined.merge(summary);
        }
        Ok(combined)
    }

    pub fn run_blocking<F>(
        &self,
        engine: &ScanEngine,
        cache: &mut ScanCache,
        stop: Arc<AtomicBool>,
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(ScanSummary),
    {
        if self.config.run_immediately {
            callback(self.run_once(engine, cache)?);
        }
        let interval = Duration::from_secs(self.config.interval_minutes.saturating_mul(60));
        while !stop.load(Ordering::Acquire) {
            let mut remaining = interval;
            while remaining > Duration::ZERO && !stop.load(Ordering::Acquire) {
                let slice = remaining.min(Duration::from_secs(1));
                thread::sleep(slice);
                remaining = remaining.saturating_sub(slice);
            }
            if !stop.load(Ordering::Acquire) {
                callback(self.run_once(engine, cache)?);
            }
        }
        Ok(())
    }
}
