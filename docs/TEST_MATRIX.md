# Matriz de testes adversariais

A matriz deve provar que falhas de integridade não transformam o updater ou a quarentena em mecanismos de perda silenciosa de dados. Os testes usam arquivos temporários e bytes sintéticos; nenhum malware é criado ou executado.

| Área | Caso | Resultado esperado | Cobertura v0.4.0 |
| --- | --- | --- | --- |
| Parser PE | Entrada não-PE | Retorna `None`, sem panic | Aprovado |
| Parser PE | Assinatura `MZ` truncada | Retorna `Malformed`, sem panic | Aprovado |
| Parser PE | Entrada acima de 64 MiB | Retorna `TooLarge` antes do parsing | Aprovado |
| Parser PE | Entropia de bytes conhecida | Resultado determinístico e limitado | Aprovado |
| Quarentena | Conteúdo original é copiado e removido | Origem ausente; sidecar presente | Aprovado no v0.3.0 |
| Quarentena | Conteúdo `.quarantined` adulterado | Restauração recusada; origem continua ausente | Aprovado |
| Quarentena | Destino original já existe | Restauração recusada sem sobrescrever | Aprovado no v0.3.0 |
| Quarentena | Destino tenta apontar para a própria quarentena | Restauração recusada | Aprovado no v0.3.0 |
| Updater | Hash correto com prefixo `sha256:` | Instala novo arquivo e preserva `.previous` | Aprovado |
| Updater | Hash divergente | Falha antes da troca; destino permanece intacto | Aprovado |
| Updater | `.download` stale existente | Falha sem sobrescrever o temporário ou destino | Aprovado |
| Updater | Falha de rename no destino | Deve restaurar backup quando possível | Cobertura de integração pendente |
| Histórico | Linha v1 válida | Registro aparece no reader/GUI | Aprovado |
| Histórico | Linha legada `ScanSummary` | Aparece como `Legacy` | Aprovado |
| Histórico | Linha JSONL corrompida | É contada e não interrompe as demais | Aprovado |
| Histórico | Arquivo muito grande | GUI retém apenas janela limitada em memória | Aprovado para janela de 200 |

## Critérios de aceite do CI

Cada caso deve ser determinístico, não depender de rede, não executar o arquivo de fixture e limpar temporários mesmo quando uma asserção falhar. Os testes que usam Windows devem rodar em `windows-latest`; os testes de API e serialização devem continuar executando também nos demais runners.

A validação de release deve baixar os ativos publicados, comparar os hashes com `SHA256SUMS.txt`, confirmar o manifesto e verificar que o updater rejeita um byte alterado. A validação Authenticode permanece separada: assinatura presente não basta sem cadeia confiável, validade e política explícita.
