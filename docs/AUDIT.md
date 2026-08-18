# Auditoria de evolução — 2026-08-18

## Baseline validado

| Funcionalidade | Situação | Evidência |
| --- | --- | --- |
| Workspace Rust Windows x64 | Concluído | `cargo check --workspace` passa no computador conectado. |
| Testes unitários | Concluído | `cargo test --workspace`: 3 testes do núcleo aprovados, incluindo SHA-256, EICAR em memória e isolamento de regra inválida. |
| SHA-256 e SQLite | Concluído | Banco local com índice por hash e seed da assinatura EICAR. |
| YARA-X | Concluído | Regras `.yar/.yara` compiladas com includes desabilitados e erros isolados. |
| CLI de scan | Concluído | `scan`, `quick-scan`, saída JSON, EICAR e quarentena implementados. |
| Dashboard desktop | Parcialmente concluído | Quick Scan, Custom Scan, explicação e ação de quarentena existem; o toggle de proteção em tempo real ainda é informativo. |
| Histórico | Parcialmente concluído | Histórico JSONL é gravado após scans; ainda falta tela de consulta, retenção e rotação. |
| Atualização via Releases | Concluído | Release `v0.1.0` pública com três EXEs, manifest e checksums; consulta local retornou a Release correta. |
| Quarentena | MVP concluído | Cópia, sidecar JSON e remoção explícita; ainda faltam ACLs restritivas, restauração controlada e limpeza. |
| Proteção em tempo real | Não implementado | Não existe watcher de diretórios, fila de análise, debounce ou processo de monitoramento persistente. |
| Full Scan | Não implementado | O CLI possui Quick Scan e alvo personalizado, mas não há seleção de unidades no dashboard. |
| Parser PE/AuthentiCode | Não implementado | Previsto na documentação para fase posterior. |

## Lacunas prioritárias

A próxima entrega deve implementar um monitor user-mode defensivo baseado em notificações do filesystem, com diretórios configuráveis, debounce, fila limitada, exclusões exatas e análise somente depois que o arquivo estiver estável. O monitor deve usar o mesmo `ScanEngine`, nunca executar o arquivo observado e registrar detecções no histórico. O MVP não deve instalar driver ou alterar o Windows Defender.

Depois do monitor, a validação deve cobrir a integração do toggle da GUI, encerramento limpo, recomeço após erro de permissão, saturação da fila, arquivo temporário e arquivo criado em Downloads/Desktop. A proteção deve ser transparente: indicar que está ativa, mostrar a última atividade e permitir desligamento explícito.
