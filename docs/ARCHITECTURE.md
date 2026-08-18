# Arquitetura

O workspace segue uma separação por responsabilidade. `crates/core` concentra o pipeline defensivo e não depende da interface; `apps/desktop` apresenta o dashboard; `apps/cli` expõe automação; `apps/updater` permanece em processo separado para trocar arquivos depois que o aplicativo principal encerra.

```text
crates/core
  ├── SignatureDatabase     SQLite com índice por SHA-256
  ├── YaraEngine            compilação isolada de regras YARA-X
  ├── ScanEngine            enumeração, hash, assinaturas e classificação
  ├── QuarantineManager     cópia, metadados e remoção explícita
  └── Release helpers       consulta, versão, download e integridade

apps/desktop                GUI egui/eframe
apps/cli                    interface de linha de comando
apps/updater                troca segura de binário fechado
rules/                      regras .yar/.yara validadas individualmente
.github/workflows            CI e publicação de Releases
```

O pipeline é deliberadamente não-executável:

```text
Enumerator
  → Metadata validation
  → SHA-256
  → SQLite signature lookup
  → YARA-X
  → sinais mínimos de teste/heurística
  → DetectionResult
  → explicação
  → quarentena mediante confirmação
```

O MVP limita o tamanho analisado por arquivo a 64 MiB para evitar consumo descontrolado de memória e ignora links simbólicos durante a enumeração. Regras inválidas são registradas como aviso e isoladas, sem interromper as demais regras. A evolução prevista inclui Full Scan, monitoramento de Downloads, Authenticode, parser PE e proteção em tempo real, sempre depois da estabilização do scanner tradicional.
