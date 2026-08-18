# Licenças de terceiros

O workspace usa dependências de código aberto gerenciadas pelo Cargo. A lista completa e os textos de licença devem ser gerados a partir do `Cargo.lock` antes de uma distribuição ampla.

| Componente | Uso | Licença upstream |
| --- | --- | --- |
| Rust standard toolchain | Compilação e runtime | Apache-2.0 / MIT |
| `eframe` e `egui` | Interface desktop | MIT / Apache-2.0 |
| `rusqlite` e SQLite bundled | Banco local de assinaturas | MIT / public domain, conforme upstream |
| `yara-x` | Compilação e execução de regras YARA defensivas | BSD-3-Clause |
| `notify` | Notificações de filesystem para proteção em tempo real | CC0-1.0 |
| `ctrlc` | Encerramento limpo do monitor CLI | MIT / Apache-2.0 |
| `reqwest` e `rustls` | Consulta HTTPS à API do GitHub e downloads | MIT / Apache-2.0 |
| `sha2`, `hex`, `serde` | Hashes, serialização e manifest | MIT / Apache-2.0 |

Não incorporar certificados, chaves privadas ou regras de terceiros sem revisar a licença e a procedência. A geração final de um `THIRD_PARTY_NOTICES` deve acompanhar o instalador quando o produto sair do MVP.
