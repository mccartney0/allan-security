use crate::default_data_dir;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ExclusionPolicy {
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub extensions: Vec<String>,
}

impl ExclusionPolicy {
    pub fn default_path() -> PathBuf {
        default_data_dir().join("exclusions.json")
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path).with_context(|| format!("lendo {}", path.display()))?;
        let mut policy: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("interpretando {}", path.display()))?;
        policy.normalize();
        policy.validate()?;
        Ok(policy)
    }

    pub fn load_default() -> Result<Self> {
        Self::load(&Self::default_path())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.flush()?;
        drop(file);
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn save_default(&self) -> Result<()> {
        self.save(&Self::default_path())
    }

    pub fn add_path(&mut self, path: &Path) -> Result<()> {
        let normalized = normalize_configured_path(path)?;
        if is_filesystem_root(&normalized) {
            return Err(anyhow!("não é permitido excluir uma raiz de volume"));
        }
        if !self
            .paths
            .iter()
            .any(|existing| path_key(existing) == path_key(&normalized))
        {
            self.paths.push(normalized);
        }
        self.normalize();
        self.validate()
    }

    pub fn remove_path(&mut self, path: &Path) -> bool {
        let key = path_key(path);
        let before = self.paths.len();
        self.paths.retain(|existing| path_key(existing) != key);
        before != self.paths.len()
    }

    pub fn add_extension(&mut self, extension: &str) -> Result<()> {
        let trimmed = extension.trim().to_ascii_lowercase();
        if trimmed.is_empty()
            || trimmed.len() > 32
            || trimmed
                .chars()
                .any(|character| matches!(character, '\\' | '/' | ':'))
        {
            return Err(anyhow!("extensão inválida: use, por exemplo, .tmp ou .log"));
        }
        let normalized = if trimmed.starts_with('.') {
            trimmed
        } else {
            format!(".{trimmed}")
        };
        if !self.extensions.contains(&normalized) {
            self.extensions.push(normalized);
        }
        self.normalize();
        self.validate()
    }

    pub fn remove_extension(&mut self, extension: &str) -> bool {
        let normalized = extension.trim().to_ascii_lowercase();
        let normalized = if normalized.starts_with('.') {
            normalized
        } else {
            format!(".{normalized}")
        };
        let before = self.extensions.len();
        self.extensions.retain(|item| item != &normalized);
        before != self.extensions.len()
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        let candidate = path_key(path);
        let path_excluded = self.paths.iter().any(|excluded| {
            let root = path_key(excluded);
            candidate == root || candidate.starts_with(&(root + "\\"))
        });
        if path_excluded {
            return true;
        }
        path.extension()
            .map(|extension| format!(".{}", extension.to_string_lossy().to_ascii_lowercase()))
            .map(|extension| self.extensions.iter().any(|item| item == &extension))
            .unwrap_or(false)
    }

    pub fn normalize(&mut self) {
        self.paths.sort_by_key(|path| path_key(path));
        self.paths
            .dedup_by(|left, right| path_key(left) == path_key(right));
        self.extensions.iter_mut().for_each(|item| {
            *item = item.trim().to_ascii_lowercase();
            if !item.starts_with('.') {
                *item = format!(".{item}");
            }
        });
        self.extensions.sort();
        self.extensions.dedup();
    }

    pub fn validate(&self) -> Result<()> {
        for path in &self.paths {
            if !path.is_absolute() {
                return Err(anyhow!(
                    "exclusão de caminho precisa ser absoluta: {}",
                    path.display()
                ));
            }
            if is_filesystem_root(path) {
                return Err(anyhow!("não é permitido excluir uma raiz de volume"));
            }
        }
        for extension in &self.extensions {
            if extension.is_empty()
                || !extension.starts_with('.')
                || extension
                    .chars()
                    .any(|character| matches!(character, '\\' | '/' | ':'))
            {
                return Err(anyhow!("extensão de exclusão inválida: {extension}"));
            }
        }
        Ok(())
    }
}

fn normalize_configured_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(anyhow!("caminho de exclusão precisa ser absoluto"));
    }
    if path.exists() {
        fs::canonicalize(path).with_context(|| format!("normalizando {}", path.display()))
    } else {
        Ok(path.to_path_buf())
    }
}

fn is_filesystem_root(path: &Path) -> bool {
    path.parent().is_none() || path.parent() == Some(path)
}

fn path_key(path: &Path) -> String {
    let mut value = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    if let Some(rest) = value.strip_prefix(r"\\?\unc\") {
        value = format!(r"\\{rest}");
    } else if let Some(rest) = value.strip_prefix(r"\\?\") {
        value = rest.to_string();
    }
    while value.ends_with('\\') && value.len() > 3 {
        value.pop();
    }
    value
}
