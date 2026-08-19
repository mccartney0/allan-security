# Backlog futuro — Allan Security

Este backlog transforma a documentação mestre em incrementos pequenos. Cada item só pode ser marcado como concluído depois de implementação real, testes locais e no CI, documentação, commit e push. A proteção em tempo real do MVP será user-mode, transparente e desativável; driver e Windows Service ficam para uma etapa posterior, depois de assinatura e instalador confiáveis.

## P0 — próxima sequência

| ID | Item | Critério de conclusão | Estado |
| --- | --- | --- | --- |
| RT-001 | Monitor de filesystem em Downloads/Desktop | Eventos create/write/rename chegam ao mesmo `ScanEngine`, sem executar arquivos, com encerramento limpo e tratamento de erro de permissão. | Concluído no MVP user-mode |
| RT-002 | Debounce e estabilidade | O monitor espera tamanho/mtime estáveis, coalesce eventos duplicados e limita a fila; arquivos em escrita parcial não são removidos. | Concluído no MVP user-mode |
| RT-003 | Exclusões explícitas | Diretórios e extensões excluídos são validados, exibidos na GUI e não podem ignorar uma detecção por hash conhecido. | Concluído no v0.3.0 |
| RT-004 | Controle no dashboard | GUI mostra ativo/inativo, último evento, último scan e permite ligar/desligar sem mensagem alarmista. | Concluído no MVP user-mode |
| QA-001 | Matriz de validação | Quick Scan, Custom Scan, YARA válido/inválido, EICAR em memória, quarentena, histórico, consulta de Release e falhas de integridade possuem testes reproduzíveis. | Parcial: baseline, quarentena/update adversarial e reader de histórico aprovados; matriz de integração completa ainda pendente |
| HIST-001 | Tela de histórico | Usuário consulta scans e detecções, com retenção/rotação documentada. | Parcial no v0.4.0: envelope v1, reader incremental, filtro e `show_rows` na GUI; rotação ainda pendente |
| QUAR-001 | Quarentena reforçada | ACL restritiva, restauração somente por ação explícita, validação de hash e limpeza segura. | Concluído no v0.3.0 |

## P1 — endurecimento do produto

| ID | Item | Critério de conclusão | Estado |
| --- | --- | --- | --- |
| RT-005 | Serviço Windows opcional | Serviço com recuperação após falha, privilégios mínimos, instalação/reparo/desinstalação e coexistência documentada com Defender. | Planejado |
| RT-006 | Monitoramento de Downloads e startup | Pastas e itens de inicialização são observados sem remoção automática. | Planejado |
| SCAN-001 | Full Scan | GUI e CLI percorrem as raízes disponíveis, aplicam a política, registram métricas e mantêm a ação de quarentena explícita; controles de pausa/retomada ficam fora deste incremento. | Concluído no v0.3.0 |
| SCAN-002 | Cache e scheduler | Cache SQLite por caminho, tamanho, mtime e chave do engine; scheduler intervalar com sinal de parada e histórico local. | Concluído no v0.3.0 |
| PE-001 | Parser PE seguro | EXE/DLL/SYS têm arquitetura, sections, imports, entry point, timestamp, entropy e Authenticode lidos sem execução. | Parcial no v0.4.0: `object` lê PE32/PE64, seções, imports, entry point, timestamp e entropy; Authenticode ainda pendente |
| HEUR-001 | Heurísticas estáticas | Score explicável com baixa taxa de falsos positivos e testes de regressão. | Planejado |
| UPD-001 | Assinatura Authenticode | Binários e updater assinados em CI por secret externo; nenhuma chave privada no Git. | Planejado |
| INST-001 | Instalador Windows | Instalação, atualização, reparo e desinstalação com opção de preservar quarentena/histórico/configuração. | Planejado |

## P2 — funcionalidades avançadas

| ID | Item | Critério de conclusão | Estado |
| --- | --- | --- | --- |
| ARCH-001 | Artefatos ARM64 | Build e testes em Windows ARM64, com asset separado e seleção de arquitetura no updater. | Planejado |
| PROC-001 | Scan de processos | Lista processo, caminho e assinatura do executável sem injeção, dumping ou manipulação invasiva. | Planejado |
| REP-001 | Reputation engine | Consultas opcionais, consentidas e transparentes, com privacidade e fallback offline. | Planejado |
| ML-001 | Modelo local auxiliar | Features estáticas, probabilidade combinada com hashes/YARA/heurísticas e testes de explicabilidade; nunca executar malware para gerar features. | Planejado |
| ARCHIVE-001 | Scan de arquivos compactados | Limites de profundidade, tamanho expandido, tempo e proteção contra zip bombs. | Planejado |

## Registro do playthrough v0.4.0

O incremento adicionou o parser PE somente leitura em `allan-core`, o comando `pe-info` no CLI, o envelope versionado do `history.jsonl`, leitura limitada aos 200 registros mais recentes com tolerância a linhas legadas/corrompidas e painel filtrável/virtualizado na GUI. Também foram adicionados testes adversariais locais para hash divergente, backup `.previous`, temporário stale do updater, quarentena adulterada e limites do parser PE.

## Definition of Done

Um item exige código real, testes unitários e de integração adequados, execução local no Windows x64, CI verde, erros tratados, documentação atualizada, nenhum botão falso, nenhuma alteração silenciosa de proteção do Windows e commit/push identificável. Para itens de detecção, o resultado deve explicar por que o arquivo foi classificado e preservar a ação do usuário quando houver incerteza.
