# Parser PE seguro

O Allan Security usa o crate `object` em modo somente leitura para reconhecer PE32/PE32+ e extrair metadados estáticos. O parser nunca carrega, mapeia ou executa o arquivo como imagem de processo; ele recebe um `&[u8]` já limitado pelo engine e devolve `PeStaticReport` serializável.

## Limites defensivos

O limite de entrada é `64 MiB`, com no máximo `96` seções, `100.000` imports e amostra de entropia de `4 MiB` por seção. Assinaturas `MZ` truncadas produzem status `Malformed` sem panic. Ranges raw que não cabem no arquivo são registrados como warning e podem ser rejeitados por `validate_report`.

## CLI

Para inspecionar um EXE, DLL ou SYS sem executar o arquivo:

```powershell
allan-security-cli.exe pe-info C:\caminho\arquivo.exe
allan-security-cli.exe pe-info C:\caminho\arquivo.exe --json
```

O relatório inclui arquitetura, bitness, machine, timestamp, entry point, seções com range raw e entropia, imports por biblioteca/nome ou ordinal e warnings. Arquivos que não começam com `MZ` são reportados como `not-pe`.

## Critérios de segurança

O parser não deve ser usado como autorização automática para executar, excluir ou restaurar arquivos. Metadados PE são evidência explicável complementar a SHA-256, banco de assinaturas e YARA. A classificação continua sujeita à política de exclusões, com a exceção de hashes conhecidos mantida no scanner.

Os testes unitários cobrem não-PE, PE truncado, entrada acima do limite e entropia determinística. O playthrough também executa `pe-info` contra o CLI Windows compilado e confirma arquitetura `X86_64`, cinco seções e imports reais sem iniciar o binário analisado.

A validação de Authenticode permanece pendente para um incremento posterior; presença de uma tabela de certificados não deve ser confundida com confiança criptográfica até que a cadeia, validade temporal e política de confiança sejam verificadas.
