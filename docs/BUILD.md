# Build e publicação

## Build local no Windows x64

O ambiente validado usa `stable-x86_64-pc-windows-msvc` e Rust 1.96.0. Na raiz:

```powershell
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo build --release -p allan-security-desktop
cargo build --release -p allan-security-cli
cargo build --release -p allan-security-updater
```

Os executáveis ficam em `target\release`. Para uma distribuição manual, copie também `rules\` para o mesmo pacote do desktop e do CLI.

## CI em cada ajuste

O workflow `ci.yml` é executado em cada push e pull request. Ele instala a toolchain MSVC x64, roda format check, check, testes e build dos três pacotes. No push para branches, os executáveis são publicados como artefato do workflow; assim cada ajuste compilado pode ser baixado sem criar uma Release semântica.

## Release semântica

Para criar uma versão distribuível:

```powershell
git add .
git commit -m "feat: descrição do ajuste"
git push origin main
git tag v0.1.0
git push origin v0.1.0
```

O workflow `release.yml` cria um draft, empacota os três binários e as regras, calcula `SHA256SUMS.txt` e `allan-security-manifest.json`, e publica a Release. O manifest contém a versão, o repositório e o SHA-256 de cada asset. Nenhum certificado ou chave privada fica no Git.

## Assinatura futura

Quando houver certificado Authenticode, o passo de assinatura deve ocorrer no runner Windows após o build e antes do empacotamento, usando secrets protegidos ou um serviço externo de code signing. A chave privada não deve ser commitada, colocada no manifest ou embutida no executável.
