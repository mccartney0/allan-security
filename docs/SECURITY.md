# Segurança

O Allan Security é uma ferramenta defensiva e foi desenhado para reduzir a superfície de risco do próprio scanner. A análise lê metadados e bytes; nenhum arquivo é aberto como processo, carregado como biblioteca ou usado para injeção. O projeto não desativa o Windows Defender, não altera políticas de segurança sem consentimento e não instala persistência furtiva.

A quarentena usa um diretório separado em `LOCALAPPDATA\AllanSecurity\quarantine`, cria um nome derivado de parte do SHA-256 e mantém um sidecar JSON com o caminho original, hash e horário. A ação é explícita e não existe restauração automática. A implementação deve futuramente adicionar ACLs restritivas e assinatura de catálogo antes de ser tratada como produto de segurança de produção.

O carregador YARA-X desabilita `include` para evitar que regras tragam dependências arbitrárias do filesystem. Cada arquivo de regra é compilado isoladamente; erros ficam registrados sem impedir o carregamento de regras válidas. O scanner também define timeout e limite de tamanho.

O atualizador baixa somente assets da Release selecionada no repositório configurado, exige SHA-256 da API ou do manifest da Release, escreve em arquivo temporário e só faz a troca após a validação. Falhas preservam o binário anterior. A assinatura Authenticode ainda não está configurada porque certificado e chave privada nunca devem ser armazenados no repositório; o workflow aceita esse passo no futuro por secret externo.

## Limites importantes

O MVP não é um EDR, não monitora processos em memória, não possui driver, não implementa proteção em tempo real e não deve ser anunciado como substituto de uma solução de endpoint. A camada de heurística ainda é deliberadamente pequena para privilegiar baixo número de falsos positivos. Não se deve classificar um arquivo como malware apenas por ausência de assinatura digital, alta entropia ou editor desconhecido.
