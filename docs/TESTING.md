# Testes

A definição de concluído exige código compilável, testes executados, tratamento de erro e documentação atualizada. O núcleo possui testes para hash determinístico, detecção do EICAR via assinatura e YARA-X, e isolamento de regra inválida.

## Execução

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

## Cenário manual EICAR

O teste padrão não é malware real. Para executar o fluxo completo sem executar conteúdo:

```powershell
cargo run -p allan-security-cli -- eicar
cargo run -p allan-security-cli -- scan "$env:TEMP\allan-security-eicar.com"
```

O resultado esperado é uma detecção `Critical`, com razões relacionadas à assinatura SHA-256 e à regra YARA. A quarentena deve ser acionada explicitamente:

```powershell
cargo run -p allan-security-cli -- quarantine "$env:TEMP\allan-security-eicar.com"
```

## Auto-updater

O workflow precisa ser validado com uma Release de teste contendo os três executáveis, `allan-security-manifest.json` e `SHA256SUMS.txt`. O teste deve confirmar que um asset com hash alterado é recusado, que um manifest de versão diferente é recusado, que a troca só ocorre com o processo-alvo fechado e que o arquivo `.previous` permanece disponível após uma troca bem-sucedida.

O updater não deve ser testado apontando para um arquivo desconhecido ou para uma URL arbitrária em produção. O repositório e o nome do asset devem ser fixados pela aplicação.
