# Allan Security

**Allan Security** é um MVP de antivírus defensivo para Windows 10/11 x64. O projeto foi estruturado em Rust porque o computador conectado já possui toolchain MSVC x64 funcional, o núcleo pode ser compartilhado entre executáveis e a linguagem oferece verificações de segurança de memória sem exigir um compilador C++ adicional. A interface usa `egui/eframe` para manter a distribuição simples no Windows; o motor de detecção usa SQLite, SHA-256 e YARA-X.

> Este projeto não substitui o Windows Defender nem outro produto de segurança. O MVP não instala driver, não injeta código, não faz dumping de memória e não executa os arquivos analisados.

## Os três executáveis

| Executável | Responsabilidade | Atualização |
| --- | --- | --- |
| `allan-security-desktop.exe` | Dashboard, Quick Scan, Custom Scan, histórico, explicação e quarentena explícita. | Consulta a Release e inicia o updater separado. |
| `allan-security-cli.exe` | Verificação automatizável, teste EICAR, saída JSON, quarentena e consulta de atualização. | Distribuído como asset independente. |
| `allan-security-updater.exe` | Consulta a última GitHub Release, baixa o asset correto, valida SHA-256 e troca o executável fechado. | Atualiza os três binários sem substituir a si mesmo durante execução. |

## Primeiro marco funcional

O fluxo implementado é **selecionar pasta ou arquivo → enumerar → calcular SHA-256 → consultar SQLite → aplicar YARA → classificar → mostrar razões → mover para quarentena somente após ação explícita → registrar histórico**. A regra EICAR é incluída apenas para teste defensivo; ela não representa malware real.

## Proteção em tempo real

O MVP agora possui proteção em tempo real **user-mode** baseada em notificações de filesystem do Windows por meio do crate `notify`, que usa `ReadDirectoryChangesW` no Windows. O monitor observa Downloads e Desktop, normaliza eventos de criação/escrita, aplica debounce, espera o arquivo ficar estável, usa o mesmo `ScanEngine` e registra o resultado em `LOCALAPPDATA\\AllanSecurity\\history.jsonl`. Ele nunca executa o arquivo observado, não instala driver e não desativa o Windows Defender.

A GUI possui o botão **Ativar/Desativar**. Ao ativar, ela inicia o `allan-security-cli.exe realtime` ao lado do desktop; ao desativar, encerra o processo. Também é possível executar diretamente:

```powershell
cargo run -p allan-security-cli -- realtime
cargo run -p allan-security-cli -- realtime "C:\\Users\\allan\\AppData\\Local\\Temp"
```

Esse modo permanece ativo enquanto o processo monitor estiver em execução. Inicialização automática no boot como Windows Service, ACLs reforçadas, recuperação após falha e assinatura Authenticode permanecem no backlog posterior.

## Como executar no Windows

```powershell
cargo run -p allan-security-desktop
cargo run -p allan-security-cli -- eicar
cargo run -p allan-security-cli -- scan "$env:TEMP\allan-security-eicar.com"
```

A GUI usa `LOCALAPPDATA\AllanSecurity` para o banco, histórico e quarentena. A quarentena copia o arquivo para uma área separada, grava metadados JSON e só então remove o original. Não existe restauração automática.

## Repositório e publicação

O repositório oficial é [github.com/mccartney0/allan-security](https://github.com/mccartney0/allan-security). Cada push executa validação, testes e build x64 no workflow `ci.yml`, deixando os três executáveis como artefatos do workflow. Uma tag semântica no formato `v0.1.0` aciona `release.yml`, que cria uma GitHub Release com os três binários, as regras e `allan-security-manifest.json` contendo os SHA-256.

A documentação do GitHub descreve Releases como pacotes de iterações do projeto que podem conter binários anexados [1]. Os workflows são arquivos YAML mantidos em `.github/workflows` e podem ser filtrados por tags e eventos [2].

## Atualizador

O desktop consulta `GET /repos/{owner}/{repo}/releases/latest`. Quando há uma versão mais nova, o usuário decide se deseja atualizar. O updater seleciona o asset correspondente à arquitetura, prioriza o digest fornecido pela API de Releases e, quando necessário, valida o `allan-security-manifest.json` antes de baixar o binário. O arquivo é gravado com extensão temporária, o SHA-256 é conferido e somente depois ocorre a troca; se a validação falhar, o binário original permanece intacto.

A atualização automática não é silenciosa: exige confirmação na interface, não desativa proteções do Windows, não executa o arquivo baixado durante a validação e falha de forma conservadora quando a Release não possui dados de integridade.

## Referências

[1]: https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository "GitHub Docs — Managing releases in a repository"
[2]: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax "GitHub Docs — Workflow syntax for GitHub Actions"
[3]: https://docs.rs/yara-x/1.19.0/yara_x/ "docs.rs — YARA-X API"
[4]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw "Microsoft Learn — ReadDirectoryChangesW"
[5]: https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-directory-change-notifications "Microsoft Learn — Obtaining Directory Change Notifications"
