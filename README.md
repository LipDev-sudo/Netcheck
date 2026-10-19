# NetCheck

Ferramenta de diagnóstico de rede em linha de comando, escrita em Python. Verifica a resolução DNS, a conexão TCP (com latência e perda) e o certificado TLS de um ou mais domínios, e salva um relatório em texto ou JSON.

## Funcionalidades

- resolução DNS do domínio informado;
- teste de conexão TCP (padrão: porta 443, timeout de 3 s) com medição do tempo de conexão;
- várias portas (`-p 80,443`) e vários domínios em uma única execução;
- várias tentativas por porta (`-n 5`) com mínimo, média, máximo e percentual de perda;
- validação do certificado TLS (`--tls`): validade, data de expiração, dias restantes e emissor;
- validação da entrada: domínio não vazio, portas entre 1 e 65535, timeout positivo;
- relatório em `reports/netcheck_AAAAMMDD_HHMMSS.txt` (ou em JSON com `--json`), sem sobrescrever relatórios do mesmo segundo;
- códigos de saída distintos para uso em scripts.

## Tecnologias

- Python 3.10 ou superior (testado no CI em 3.10, 3.11, 3.12 e 3.13)
- Biblioteca padrão (`socket`, `ssl`, `argparse`, `statistics`), sem dependências externas
- `unittest`, `ruff` e GitHub Actions para testes, lint e cobertura

## Como executar

```bash
git clone https://github.com/LipDev-sudo/Netcheck.git
cd Netcheck
python3 netcheck.py
```

Sem argumentos, o programa pergunta o domínio e a(s) porta(s) (Enter usa 443). Também aceita argumentos:

```bash
python3 netcheck.py example.com                      # porta 443
python3 netcheck.py example.com -p 80,443 -t 5       # duas portas, timeout de 5 s
python3 netcheck.py example.com -n 5                 # 5 conexões por porta, com estatísticas
python3 netcheck.py example.com --tls                # valida o certificado TLS
python3 netcheck.py example.com github.com --json   # vários domínios, saída em JSON
python3 netcheck.py example.com --sem-relatorio      # não grava arquivo
python3 netcheck.py --help
```

### Instalação como comando (opcional)

```bash
python3 -m pip install .
netcheck example.com --tls
```

| Opção | Descrição |
| --- | --- |
| `dominio...` | um ou mais domínios a testar |
| `-p`, `--porta` | porta TCP ou lista separada por vírgula (padrão 443) |
| `-t`, `--timeout` | tempo limite em segundos (padrão 3) |
| `-n`, `--tentativas` | conexões por porta, de 1 a 100 (padrão 1) |
| `--tls` | valida o certificado TLS (na 443, se listada; senão, na primeira porta) |
| `--json` | imprime e salva o resultado em JSON |
| `--sem-relatorio` | não salva o relatório |
| `-o`, `--pasta` | pasta dos relatórios (padrão `reports`) |
| `-V`, `--version` | mostra a versão |

### Saída JSON

```json
{
  "resultados": [
    {
      "data_hora": "2026-10-19T19:44:05-03:00",
      "dominio": "example.com",
      "ip": "104.20.23.154",
      "dns": true,
      "portas": [
        {
          "porta": 443, "tentativas": 3, "sucessos": 3, "perda_pct": 0.0,
          "conectividade": true, "tempo_conexao_ms": 113.24, "min_ms": 109.8, "max_ms": 119.43
        }
      ],
      "tls": { "porta": 443, "valido": true, "expira_em": "2026-12-25T22:56:35+00:00",
               "dias_restantes": 67, "emissor": "SSL Corporation", "erro": null }
    }
  ]
}
```

`tls` é `null` quando `--tls` não é usado; `portas` fica vazio quando o DNS falha.

### Códigos de saída

| Código | Significado |
| --- | --- |
| 0 | tudo funcionou: DNS, todas as portas e, se pedido, o certificado TLS |
| 1 | falha de DNS, de conexão em alguma porta ou certificado TLS inválido/expirado |
| 2 | entrada inválida (domínio vazio, porta fora de 1–65535, timeout ≤ 0, tentativas fora de 1–100) |

## Testes

```bash
python3 -m unittest discover -s tests -v
```

Os testes usam simulações (mocks) e não dependem de acesso à rede. O workflow em `.github/workflows/tests.yml` executa a cada push e pull request na `main`: lint (`ruff`), testes em Python 3.10 a 3.13, instalação como pacote e cobertura mínima de 80%.

## Estrutura do projeto

```text
netcheck/
├── netcheck.py            # CLI e funções de diagnóstico
├── pyproject.toml         # pacote (comando `netcheck`) e configuração do ruff
├── tests/
│   └── test_netcheck.py
├── .github/workflows/tests.yml
└── reports/               # criada ao gerar relatórios
```

## Objetivo

Projeto de estudo voltado para diagnóstico de redes, automação de tarefas e testes automatizados, aplicando conceitos úteis para suporte técnico e infraestrutura de TI.

## Limitações

Não executa ping ICMP, traceroute nem varredura de portas, e resolve apenas endereços IPv4.
