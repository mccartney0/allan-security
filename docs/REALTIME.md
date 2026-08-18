# Proteção em tempo real

## Escopo do MVP

A proteção em tempo real é um monitor **user-mode**. O processo observa Downloads e Desktop por notificações de filesystem, enfileira caminhos modificados, agrupa eventos próximos, aguarda tamanho e horário de modificação estáveis e então chama o mesmo `ScanEngine` usado pelo Quick Scan e pelo Custom Scan. O monitor não abre processos, não executa arquivos, não injeta código, não instala driver e não desativa o Windows Defender.

A escolha de `ReadDirectoryChangesW` via `notify` permite obter caminhos e tipos específicos de mudança. A API exige acesso de listagem ao diretório monitorado e pode perder detalhes quando o buffer de notificações transborda; por isso, o monitor limita a fila, emite aviso e mantém uma estratégia conservadora de não apagar arquivos quando o evento está incompleto [1]. A documentação de notificações de diretório também orienta escolher uma abordagem — `ReadDirectoryChangesW` ou `FindFirstChangeNotification` — sem combiná-las [2].

## Fluxo

| Etapa | Comportamento |
| --- | --- |
| Observação | `notify` recebe eventos recursivos de criação e modificação. |
| Filtragem | Links, diretórios sem extensão e caminhos explicitamente excluídos não entram no scan. |
| Debounce | Eventos do mesmo ciclo são acumulados por 600 ms. |
| Estabilidade | O tamanho e o `mtime` precisam ficar iguais por uma janela de 250 ms; até oito tentativas são permitidas. |
| Análise | O arquivo é lido, hasheado, consultado no SQLite e avaliado pelo YARA-X. |
| Ação | A detecção é registrada e exibida; quarentena exige ação explícita. |
| Histórico | Um `ScanSummary` é anexado a `LOCALAPPDATA\\AllanSecurity\\history.jsonl`. |

## Operação

Na GUI, o botão **Ativar** inicia um processo CLI irmão com `realtime`; **Desativar** encerra esse processo. No terminal, `allan-security-cli.exe realtime` usa Downloads e Desktop. Um ou mais caminhos podem ser passados para uma sessão de teste ou implantação controlada:

```powershell
allan-security-cli.exe realtime
allan-security-cli.exe realtime "C:\\Users\\allan\\Downloads"
```

O smoke test reproduzível em `tests/realtime_smoke.ps1` inicia o monitor, cria um arquivo benigno, espera o debounce e verifica que o histórico foi criado e recebeu um resultado. O teste não usa a string EICAR no disco porque o Windows Defender pode bloqueá-la antes que o Allan Security a leia; a detecção EICAR é validada em memória pela suíte Rust.

## Limites e próximos passos

O modo atual não inicia sozinho no boot e não promete proteção de kernel. O item `RT-005` do backlog cobre um Windows Service opcional com privilégios mínimos, recuperação após falha, instalador, desinstalador, ACLs e coexistência documentada com o Defender. A assinatura Authenticode do updater e dos três binários deve ser concluída antes de distribuição ampla.

## Referências

[1]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw "Microsoft Learn — ReadDirectoryChangesW function"
[2]: https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-directory-change-notifications "Microsoft Learn — Obtaining Directory Change Notifications"
