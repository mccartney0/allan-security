# Threat model

## Ativos

Os ativos principais são os binários do Allan Security, o banco local de assinaturas, as regras YARA, o histórico de scans, a quarentena e a integridade dos assets publicados no GitHub.

## Superfícies de ataque

O scanner processa caminhos fornecidos pelo usuário e bytes potencialmente hostis. O updater consome a API pública do GitHub e baixa assets de Releases. A GUI aceita seleção de arquivos e pastas. O banco SQLite pode ser corrompido por interrupção ou falta de espaço. O workflow de publicação é uma fronteira de cadeia de suprimentos.

## Ameaças e mitigação

| Ameaça | Mitigação atual |
| --- | --- |
| Arquivo analisado tentando executar código | Arquivos são tratados como bytes; o MVP não executa, carrega ou injeta. |
| Regra YARA inválida ou lenta | Compilação isolada, includes desabilitados, timeout e descarte da regra inválida. |
| Symlink levando o scan para outra árvore | Links simbólicos são ignorados na enumeração inicial. |
| Falso positivo | Hash, YARA e sinais são apresentados com razões; não há remoção automática. |
| Download de Release adulterado | SHA-256 do asset ou manifest é conferido antes da troca. |
| Falha durante atualização | Arquivo temporário e backup `.previous`; a troca acontece só depois da validação. |
| Exposição de segredo no CI | O workflow não precisa de chave privada; signing futuro deverá usar secret externo. |
| Desativação silenciosa do Defender | Proibida pela arquitetura e pela documentação de segurança. |

## Riscos residuais

A ausência de Authenticode e de assinatura criptográfica do manifest impede tratar o canal como uma cadeia de confiança completa. A API e as Releases devem permanecer sob controle do proprietário do repositório e o repositório não deve receber workflows de pull request não revisados com permissões de escrita. Antes de uma distribuição ampla, adicionar assinatura Authenticode, pinning/revisão de Actions, ACL de quarentena, rollback testado e revisão independente do updater.
