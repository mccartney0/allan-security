use allan_core::{
    download_bytes, download_verified, latest_release, sha256_bytes, GitHubRelease,
    ReleaseManifest, VERSION,
};
use anyhow::{anyhow, Context, Result};
use std::{env, path::PathBuf, thread, time::Duration};

fn main() -> Result<()> {
    let options = Options::parse(env::args().skip(1))?;
    if options.repo.is_empty() || options.asset.is_empty() || options.target.as_os_str().is_empty()
    {
        return Err(anyhow!("uso: allan-security-updater --repo owner/repo --asset nome.exe --target caminho\\app.exe"));
    }

    let release = latest_release(&options.repo)?;
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == options.asset)
        .ok_or_else(|| {
            anyhow!(
                "asset '{}' não encontrado na Release {}",
                options.asset,
                release.tag_name
            )
        })?;
    let digest = resolve_digest(&release, asset)?;

    if let Some(pid) = options.pid {
        wait_for_process(pid);
    }
    if let Some(parent) = options.target.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("criando {}", parent.display()))?;
    }
    download_verified(&asset.browser_download_url, &options.target, &digest)
        .with_context(|| format!("instalando {}", options.target.display()))?;
    println!(
        "Atualização {} instalada em {}",
        release.tag_name,
        options.target.display()
    );
    Ok(())
}

fn resolve_digest(release: &GitHubRelease, asset: &allan_core::GitHubAsset) -> Result<String> {
    if let Some(digest) = &asset.digest {
        return Ok(digest.clone());
    }

    let manifest_asset = release
        .assets
        .iter()
        .find(|candidate| candidate.name == "allan-security-manifest.json")
        .ok_or_else(|| anyhow!("a Release não fornece digest nem manifest de integridade"))?;
    let manifest_bytes = download_bytes(&manifest_asset.browser_download_url)?;
    if let Some(manifest_digest) = &manifest_asset.digest {
        let actual = sha256_bytes(&manifest_bytes);
        if !actual.eq_ignore_ascii_case(manifest_digest.trim_start_matches("sha256:")) {
            return Err(anyhow!("integridade do manifest divergente"));
        }
    }
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)?;
    let version = release.tag_name.trim_start_matches('v');
    if manifest.version.trim_start_matches('v') != version {
        return Err(anyhow!(
            "manifest não corresponde à Release {}",
            release.tag_name
        ));
    }
    manifest
        .assets
        .iter()
        .find(|candidate| candidate.name == asset.name)
        .map(|candidate| candidate.sha256.clone())
        .ok_or_else(|| anyhow!("asset {} não possui SHA-256 no manifest", asset.name))
}

fn wait_for_process(pid: u32) {
    // O aplicativo chamador fecha antes da troca. O atraso pequeno cobre a liberação
    // de handles no Windows sem instalar serviço ou executar técnicas invasivas.
    let _ = pid;
    thread::sleep(Duration::from_secs(2));
}

struct Options {
    repo: String,
    asset: String,
    target: PathBuf,
    pid: Option<u32>,
}

impl Options {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let mut options = Self {
            repo: String::new(),
            asset: String::new(),
            target: PathBuf::new(),
            pid: None,
        };
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--repo" => {
                    options.repo = args.next().ok_or_else(|| anyhow!("--repo requer valor"))?
                }
                "--asset" => {
                    options.asset = args.next().ok_or_else(|| anyhow!("--asset requer valor"))?
                }
                "--target" => {
                    options.target = PathBuf::from(
                        args.next()
                            .ok_or_else(|| anyhow!("--target requer valor"))?,
                    )
                }
                "--pid" => {
                    options.pid = Some(
                        args.next()
                            .ok_or_else(|| anyhow!("--pid requer valor"))?
                            .parse()?,
                    )
                }
                "--help" => {
                    return Err(anyhow!(
                        "uso: --repo owner/repo --asset nome.exe --target caminho\\app.exe"
                    ))
                }
                other => return Err(anyhow!("argumento desconhecido: {other}")),
            }
        }
        Ok(options)
    }
}

#[allow(dead_code)]
fn current_version() -> &'static str {
    VERSION
}
