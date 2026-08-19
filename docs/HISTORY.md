# Histórico operacional

O histórico local fica em `%LOCALAPPDATA%\AllanSecurity\history.jsonl`. A partir do v0.4.0, CLI, GUI e monitor realtime gravam um envelope JSONL com `schema_version: 1`.

Cada registro possui timestamp UTC, origem (`Cli`, `Desktop`, `Realtime`, `Scheduler`, `Updater`), ação (`ScanCompleted`, `ThreatDetected`, `Quarantined`, `Restored`, `Error` ou `Warning`), caminho opcional, `ScanSummary` opcional e erro opcional.

O reader central `read_history` processa o arquivo linha a linha e mantém somente os registros mais recentes solicitados pela chamada. A GUI carrega no máximo 200 registros, atualiza automaticamente a cada dois segundos e usa `ScrollArea::show_rows` para virtualizar as linhas visíveis. O filtro textual procura em origem, ação, caminho e mensagem de erro.

Linhas vazias são ignoradas. Linhas JSONL v1 inválidas são contabilizadas e não interrompem a leitura. Registros legados que contenham apenas um `ScanSummary` continuam sendo exibidos como origem `Legacy`. O painel mostra a quantidade de linhas inválidas para que o usuário não confunda ausência de eventos com corrupção parcial do log.

## Retenção

O v0.4.0 limita a leitura em memória, mas ainda não realiza rotação física do arquivo. A rotação por tamanho/idade e exportação controlada são itens posteriores. Enquanto a rotação não estiver implementada, o arquivo deve ser protegido pelas ACLs da pasta de dados e a GUI não deve reescrevê-lo de forma destrutiva.

## Testes

A suíte cobre writer/reader, compatibilidade com uma linha legada, linha corrompida e retenção dos dois registros mais recentes. O smoke test realtime confirma que uma alteração observada grava um evento no mesmo `history.jsonl` usado pela aplicação.
